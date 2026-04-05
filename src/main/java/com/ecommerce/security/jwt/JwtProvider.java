package com.ecommerce.security.jwt;

import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.util.Date;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Provider responsible for issuing JWTs using RSA Asymmetric Cryptography.
 *
 * <p>This provider is explicitly meant for the token issuer (e.g., auth-service).
 */
@Service
public class JwtProvider {

  @Value("${jwt.expiration-ms:86400000}")
  private long expirationMillis;

  private final KeyPair keyPair;

  /**
   * KeyPair is injected if available. In scenarios where this library is imported by non-issuing
   * services, KeyPair will be null.
   */
  public JwtProvider(@Autowired(required = false) KeyPair keyPair) {
    this.keyPair = keyPair;
  }

  public String generateToken(String subject, Map<String, Object> claims) {
    if (keyPair == null) {
      throw new IllegalStateException("RSA KeyPair is not initialized for signing tokens.");
    }

    return Jwts.builder()
        .header()
        .keyId("ecommerce-key-1")
        .and()
        .subject(subject)
        .claims(claims)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + expirationMillis))
        .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
        .compact();
  }
}
