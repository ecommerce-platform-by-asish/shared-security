package com.app.security.token;

import com.app.security.configuration.SecurityProperties;
import com.app.security.exception.KeyPairNotInitializedException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JwtProvider {

  private final SecurityProperties properties;
  private final KeyPair keyPair;

  public String generateToken(String subject, Map<String, Object> claims) {
    var now = Instant.now();
    var builder =
        Jwts.builder()
            .header()
            .keyId(properties.jwt().keyId())
            .and()
            .id(UUID.randomUUID().toString())
            .subject(subject)
            .claims(claims)
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plusMillis(properties.jwt().expirationMs())));

    if (keyPair != null) {
      return builder.signWith(keyPair.getPrivate(), Jwts.SIG.RS256).compact();
    } else if (properties.jwt().secretKey() != null && !properties.jwt().secretKey().isBlank()) {
      return builder.signWith(getSecretKey(), Jwts.SIG.HS256).compact();
    } else {
      throw new KeyPairNotInitializedException("signing");
    }
  }

  private SecretKey getSecretKey() {
    return Keys.hmacShaKeyFor(properties.jwt().secretKey().getBytes(StandardCharsets.UTF_8));
  }
}
