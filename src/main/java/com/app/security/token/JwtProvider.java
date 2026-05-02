package com.app.security.token;

import com.app.security.configuration.SecurityProperties;
import com.app.security.exception.KeyPairNotInitializedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;

/** Utility for generating and validating RSA/HMAC-signed JWT tokens. */
@RequiredArgsConstructor
public class JwtProvider {

  private final SecurityProperties properties;
  private final KeyPair keyPair;

  /** Generates a signed JWT with the provided subject and custom claims. */
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

    return Optional.ofNullable(keyPair)
        .map(kp -> builder.signWith(kp.getPrivate(), Jwts.SIG.RS256).compact())
        .or(
            () ->
                Optional.ofNullable(properties.jwt().secretKey())
                    .filter(s -> !s.isBlank())
                    .map(s -> builder.signWith(getSecretKey(), Jwts.SIG.HS256).compact()))
        .orElseThrow(() -> new KeyPairNotInitializedException("signing"));
  }

  /** Parses and validates the provided JWT, returning its claims if successful. */
  public Jws<Claims> parseToken(String token) {
    var parser = Jwts.parser();
    Optional.ofNullable(keyPair)
        .map(KeyPair::getPublic)
        .ifPresentOrElse(parser::verifyWith, () -> parser.verifyWith(getSecretKey()));
    return parser.build().parseSignedClaims(token);
  }

  private SecretKey getSecretKey() {
    return Keys.hmacShaKeyFor(properties.jwt().secretKey().getBytes(StandardCharsets.UTF_8));
  }
}
