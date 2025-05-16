package de.jodegen.auth.service;

import de.jodegen.auth.model.UserAccount;
import de.jodegen.auth.repository.*;
import de.jodegen.auth.rest.dto.*;
import io.jsonwebtoken.JwtException;
import lombok.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserAccountRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final JwtService jwtService;

    public TokenPairResponse register(@NonNull RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already in use");
        }

        String encodedPassword = passwordEncoder.encode(request.password());
        UserAccount user = new UserAccount(request.email(), encodedPassword);

        userRepository.save(user);
        return tokenService.generateTokenPair(user);
    }

    public TokenPairResponse login(@NonNull AuthRequest request) {
        UserAccount user = userRepository.findByEmailIgnoreCase(request.email())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new RuntimeException("Invalid credentials");
        }

        return tokenService.generateTokenPair(user);
    }

    public TokenPairResponse refreshToken(@NonNull String refreshToken) {
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
}
