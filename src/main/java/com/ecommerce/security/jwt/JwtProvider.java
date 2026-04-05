package com.ecommerce.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtProvider {

  @Value("${jwt.secret-key:}")
  private String secretKeyContent;

  @Value("${jwt.expiration-ms:86400000}")
  private long expirationMillis;

  private SecretKey secretKey;

  @PostConstruct
  public void init() {
    if (secretKeyContent == null || secretKeyContent.isBlank()) {
      return;
    }

    try {
      this.secretKey = Keys.hmacShaKeyFor(secretKeyContent.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new RuntimeException(
          "Could not initialize secret key from property 'jwt.secret-key'.", e);
    }
  }

  public String generateToken(String subject, Map<String, Object> claims) {
    if (secretKey == null) {
      throw new IllegalStateException("Secret Key not initialized.");
    }

    return Jwts.builder()
        .subject(subject)
        .claims(claims)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + expirationMillis))
        .signWith(secretKey)
        .compact();
  }

  public Claims validateToken(String token) {
    if (secretKey == null) {
      throw new IllegalStateException("Secret Key not initialized.");
    }

    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
  }
}
