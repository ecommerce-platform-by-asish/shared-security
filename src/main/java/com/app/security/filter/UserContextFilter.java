package com.app.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Populates Spring Security context from incoming user identity headers. */
public class UserContextFilter extends OncePerRequestFilter {

  public static final String USER_ID_HEADER = "X-User-Id";
  public static final String USER_ROLE_HEADER = "X-User-Role";

  /** Extracts user ID and roles from request headers to set the Spring Security Authentication. */
  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String userId = request.getHeader(USER_ID_HEADER);
    String role = request.getHeader(USER_ROLE_HEADER);

    if (userId != null) {
      var authorities =
          role != null
              ? Arrays.stream(role.split(","))
                  .map(String::trim)
                  .map(String::toUpperCase)
                  .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                  .map(SimpleGrantedAuthority::new)
                  .toList()
              : java.util.Collections.<SimpleGrantedAuthority>emptyList();

      var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      // Seed userId into MDC so every downstream log line includes it automatically
      MDC.put("userId", userId);
    }

    try {
      filterChain.doFilter(request, response);
    } finally {
      MDC.remove("userId");
    }
  }
}
