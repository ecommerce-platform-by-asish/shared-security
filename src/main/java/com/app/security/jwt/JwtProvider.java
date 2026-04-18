package com.app.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Provides functionality for generating and extracting JWT tokens. */
@Service
@RequiredArgsConstructor(onConstructor_ = @Autowired(required = false))
public class JwtProvider {

  @Value("${jwt.expiration-ms:86400000}")
  private long expirationMillis;

  @Value("${jwt.key-id:common-auth-key-1}")
  private String keyId;

  private final KeyPair keyPair;

  public String generateToken(String subject, Map<String, Object> claims) {
    if (keyPair == null) {
      throw new IllegalStateException("RSA KeyPair is not initialized for signing tokens.");
    }

    return Jwts.builder()
        .header()
        .keyId(keyId)
        .and()
        .id(UUID.randomUUID().toString())
        .subject(subject)
        .claims(claims)
        .issuedAt(Date.from(Instant.now()))
        .expiration(Date.from(Instant.now().plusMillis(expirationMillis)))
        .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
        .compact();
  }

  public Claims extractClaims(String token) {
    if (keyPair == null) {
      throw new IllegalStateException("RSA KeyPair is not initialized for verifying tokens.");
    }
    return Jwts.parser()
        .verifyWith(keyPair.getPublic())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }
}
