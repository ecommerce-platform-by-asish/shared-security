package com.app.security.configuration;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Type-safe configuration for security settings. */
@ConfigurationProperties(prefix = "app.security")
public record SecurityProperties(
    @DefaultValue List<String> publicPaths,
    @DefaultValue Jwt jwt,
    @DefaultValue Rsa rsa,
    @DefaultValue Cors cors) {

  /** Configuration properties for Cross-Origin Resource Sharing (CORS). */
  public record Cors(
      @DefaultValue("*") List<String> allowedOrigins,
      @DefaultValue({"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"})
          List<String> allowedMethods,
      @DefaultValue("*") List<String> allowedHeaders,
      @DefaultValue("true") boolean allowCredentials) {}

  public record Jwt(
      @DefaultValue("86400000") long expirationMs,
      @DefaultValue("common-auth-key-1") String keyId,
      String secretKey,
      String jwkSetUri) {}

  public record Rsa(@DefaultValue("true") boolean generate) {}
}
