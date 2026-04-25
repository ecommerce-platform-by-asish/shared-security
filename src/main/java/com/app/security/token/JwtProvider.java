package com.app.security.token;

import com.app.security.configuration.SecurityProperties;
import com.app.security.exception.KeyPairNotInitializedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtProvider {

  private final SecurityProperties properties;
  private final KeyPair keyPair;

  public String generateToken(String subject, Map<String, Object> claims) {
    var kp = requireKeyPair("signing");
    var now = Instant.now();
    return Jwts.builder()
        .header()
        .keyId(properties.jwt().keyId())
        .and()
        .id(UUID.randomUUID().toString())
        .subject(subject)
        .claims(claims)
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plusMillis(properties.jwt().expirationMs())))
        .signWith(kp.getPrivate(), Jwts.SIG.RS256)
        .compact();
  }

  public Claims extractClaims(String token) {
    return Jwts.parser()
        .verifyWith(requireKeyPair("verifying").getPublic())
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  private KeyPair requireKeyPair(String operation) {
    if (keyPair == null) {
      throw new KeyPairNotInitializedException(operation);
    }
    return keyPair;
  }
}
