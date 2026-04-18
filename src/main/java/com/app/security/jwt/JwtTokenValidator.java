package com.app.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Service for validating JWT tokens used across microservices. */
@Service
public class JwtTokenValidator {

  @Value("${jwt.secret-key:}")
  private String secretKeyContent;

  private SecretKey secretKey;

  @PostConstruct
  public void init() {
    if (secretKeyContent == null || secretKeyContent.isBlank()) {
      return;
    }

    try {
      // Create a HMAC-SHA key from the secret string
      this.secretKey = Keys.hmacShaKeyFor(secretKeyContent.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new RuntimeException(
          "Could not initialize secret key from property 'jwt.secret-key'. "
              + "Ensure it is at least 32 characters (256 bits) long.",
          e);
    }
  }

  public Claims validateToken(String token) {
    if (secretKey == null) {
      throw new IllegalStateException(
          "Secret Key not initialized. Please provide 'jwt.secret-key' property.");
    }

    return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload();
  }
}
