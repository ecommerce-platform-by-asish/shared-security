package com.ecommerce.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtProvider {

  @Value("${jwt.expiration-ms:86400000}")
  private long expirationMillis;

  private final KeyPair keyPair;

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
        .id(UUID.randomUUID().toString())
        .subject(subject)
        .claims(claims)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + expirationMillis))
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
