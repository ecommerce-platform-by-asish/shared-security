package com.app.security.util;

import com.app.security.configuration.SecurityProperties;
import com.app.security.model.SecurityConstants;
import io.micrometer.tracing.CurrentTraceContext;
import io.micrometer.tracing.TraceContext;
import io.micrometer.tracing.Tracer;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.experimental.UtilityClass;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.cors.CorsConfiguration;

/** Utility class for security-related operations across the fleet. */
@UtilityClass
public class SecurityUtils {

  /**
   * Resolves the user ID from the given Authentication object. Handles JWT-based authentication
   * (extracting a specific claim) and falls back to the authentication name or an anonymous
   * identifier.
   */
  public static String resolveUserId(@Nullable Authentication auth) {
    if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
      return SecurityConstants.ANONYMOUS_USER;
    }
    if (auth.getPrincipal() instanceof Jwt jwt) {
      return Optional.ofNullable(jwt.getClaimAsString(SecurityConstants.CLAIM_USER_ID))
          .orElseGet(auth::getName);
    }
    return auth.getName();
  }

  /** Resolves the current trace ID from the tracer, falling back to a default "none" indicator. */
  public static String resolveTraceId(@Nullable Tracer tracer) {
    return Optional.ofNullable(tracer)
        .map(Tracer::currentTraceContext)
        .map(CurrentTraceContext::context)
        .map(TraceContext::traceId)
        .orElse(SecurityConstants.NONE);
  }

  /**
   * Parses a comma-separated role string into a list of GrantedAuthorities, ensuring each role has
   * the standard "ROLE_" prefix and is in upper case.
   */
  public static List<SimpleGrantedAuthority> parseAuthorities(String role) {
    return Stream.ofNullable(role)
        .flatMap(r -> Arrays.stream(r.split(",")))
        .map(String::trim)
        .filter(r -> !r.isBlank())
        .map(String::toUpperCase)
        .map(
            r ->
                r.startsWith(SecurityConstants.ROLE_PREFIX) ? r : SecurityConstants.ROLE_PREFIX + r)
        .map(SimpleGrantedAuthority::new)
        .toList();
  }

  /** Creates a UsernamePasswordAuthenticationToken for a given user and role string. */
  public static Authentication createAuthentication(String userId, String role) {
    return new UsernamePasswordAuthenticationToken(userId, null, parseAuthorities(role));
  }

  /** Builds a standard CorsConfiguration from the provided properties. */
  public static CorsConfiguration buildCors(SecurityProperties.Cors cors) {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOriginPatterns(cors.allowedOrigins());
    config.setAllowedMethods(cors.allowedMethods());
    config.setAllowedHeaders(cors.allowedHeaders());
    config.setAllowCredentials(cors.allowCredentials());
    return config;
  }
}
