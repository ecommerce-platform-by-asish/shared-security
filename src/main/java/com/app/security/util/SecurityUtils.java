package com.app.security.util;

import com.app.security.model.SecurityConstants;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import lombok.experimental.UtilityClass;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/** Utility class for security-related operations across the fleet. */
@UtilityClass
public class SecurityUtils {

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
                r.startsWith(SecurityConstants.ROLE_PREFIX)
                    ? r
                    : SecurityConstants.ROLE_PREFIX + r)
        .map(SimpleGrantedAuthority::new)
        .toList();
  }

  /** Creates a UsernamePasswordAuthenticationToken for a given user and role string. */
  public static Authentication createAuthentication(String userId, String role) {
    return new UsernamePasswordAuthenticationToken(userId, null, parseAuthorities(role));
  }
}
