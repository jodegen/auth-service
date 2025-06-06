package de.jodegen.auth.service;

import de.jodegen.auth.exception.InvalidTokenException;
import de.jodegen.auth.model.*;
import de.jodegen.auth.repository.*;
import de.jodegen.auth.rest.dto.TokenPairResponse;
import lombok.*;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtService jwtService;
    private final RefreshTokenRepository refreshTokenRepository;

    public TokenPairResponse generateTokenPair(@NonNull UserAccount userAccount) {
        String accessToken = jwtService.generateToken(userAccount);
        String refreshTokenValue = UUID.randomUUID().toString();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(userAccount);
        refreshToken.setToken(refreshTokenValue);
        refreshToken.setExpiryDate(LocalDateTime.now().plusDays(7));

        refreshTokenRepository.save(refreshToken);

        return new TokenPairResponse(accessToken, refreshTokenValue);
    }

    public TokenPairResponse refreshAccessToken(@NonNull String refreshTokenValue) {
        RefreshToken storedToken = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        if (storedToken.isExpired()) {
            refreshTokenRepository.delete(storedToken);
            throw new InvalidTokenException("Refresh token expired");
        }

        refreshTokenRepository.delete(storedToken);

        return generateTokenPair(storedToken.getUser());
    }
}
