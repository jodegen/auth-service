package de.jodegen.auth.service;

import de.jodegen.auth.model.UserAccount;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
@Slf4j
@RequiredArgsConstructor
public class JwtService {

    @Value("${jwt.expiration}")
    private long jwtExpirationMs;

    @Value("${jwt.secret}")
    private String secret;

    private SecretKey secretKey;

    @PostConstruct
    public void init() {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String generatePendingToken(@NonNull UserAccount userAccount) {
        log.info("Generating pending token for {}", userAccount);

        return Jwts.builder()
                .setSubject(userAccount.getId().toString())
                .claim("multi_factor_pending", true)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 5 * 60 * 1000)) // 5 minutes
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateToken(@NonNull UserAccount user) {
        return Jwts.builder()
                .setSubject(user.getId().toString())
                .claim("email", user.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public Claims parseToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUserId(@NonNull String token) {
        return parseToken(token).getSubject();
    }

    public void validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
        } catch (SecurityException e) {
            throw new JwtException("Invalid JWT signature", e);
        } catch (JwtException e) {
            throw new JwtException("Invalid JWT", e);
        }
    }

    public boolean isPendingToken(@NonNull String token) {
        Claims claims = parseToken(token);
        Boolean pending = claims.get("multi_factor_pending", Boolean.class);
        return pending != null && pending;
    }
}
