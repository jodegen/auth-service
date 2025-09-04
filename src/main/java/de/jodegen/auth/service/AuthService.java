package de.jodegen.auth.service;

import de.jodegen.auth.model.UserAccount;
import de.jodegen.auth.model.dto.*;
import de.jodegen.auth.repository.*;
import de.jodegen.auth.rest.dto.*;
import io.jsonwebtoken.JwtException;
import jakarta.annotation.Nullable;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.*;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserAccountRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final JwtService jwtService;

    private final ConcurrentHashMap<Long, MfaEntry> pendingMfaCodes = new ConcurrentHashMap<>();

    public LoginResponse register(@NonNull RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already in use");
        }

        String encodedPassword = passwordEncoder.encode(request.password());
        UserAccount user = new UserAccount(request.email(), encodedPassword);

        userRepository.save(user);
        return tokenService.generateTokenPair(user);
    }

    public LoginResponse login(@NonNull AuthRequest request) {
        UserAccount user = userRepository.findByEmailIgnoreCase(request.email())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        if (user.isMultiFactorEnabled()) {
            log.info("Multi Factor Authentication is enabled for user {}", user.getId());
            String generatedCode = generateMultiFactorCode(user);

            log.info("Generated MFA code for user {}: {}", user.getId(), generatedCode);
            // TODO: Send the generatedCode via email (NotificationService)

            String pendingToken = tokenService.generatePendingToken(user);
            return new LoginResponse(true, pendingToken, null, null);
        }

        return tokenService.generateTokenPair(user);
    }

    public LoginResponse verifyMultiFactor(@NonNull String mfaCode) {
        JwtUserDetails loggedInUserAccount = getLoggedInUserAccount();

        if (loggedInUserAccount == null) {
            throw new RuntimeException("No UserAccount found in SecurityContext.");
        }

        UserAccount userAccount = userRepository.findByEmailIgnoreCase(loggedInUserAccount.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid MFA code"));

        MfaEntry mfaEntry = getMfaEntry(userAccount);
        if (mfaEntry == null) {
            throw new RuntimeException("No pending MFA code found or code expired");
        }

        if (mfaEntry.code() == null || !mfaEntry.code().equals(mfaCode)) {
            throw new RuntimeException("Invalid MFA code");
        }

        return tokenService.generateTokenPair(userAccount);
    }

    public LoginResponse refreshToken(@NonNull String refreshToken) {
        return tokenService.refreshAccessToken(refreshToken);
    }

    public void logout(@NonNull String refreshToken) {
        refreshTokenRepository.findByToken(refreshToken)
                .ifPresent(refreshTokenRepository::delete);
    }

    public boolean validateToken(String token) {
        try {
            jwtService.validateToken(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public MfaEntry getMfaEntry(@NonNull UserAccount userAccount) {
        MfaEntry entry = pendingMfaCodes.get(userAccount.getId());
        if (entry == null || entry.expiresAt().isBefore(Instant.now())) {
            pendingMfaCodes.remove(userAccount.getId());
            return null;
        }
        return entry;
    }

    public String generateMultiFactorCode(@NonNull UserAccount userAccount) {
        String code = String.format("%06d", new SecureRandom().nextInt(1_000_000));
        Instant expiry = Instant.now().plusSeconds(300);
        pendingMfaCodes.put(userAccount.getId(), new MfaEntry(code, expiry));

        return code;
    }

    @Nullable
    private JwtUserDetails getLoggedInUserAccount() {
        var securityContext =
                SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (securityContext instanceof JwtUserDetails) {
            return (JwtUserDetails) securityContext;
        }

        log.warn("No UserAccount found in SecurityContext.");
        return null;
    }

}
