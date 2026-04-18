package com.app.security.filter;

import io.micrometer.tracing.Tracer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Populates Spring Security context from incoming user identity headers. */
@RequiredArgsConstructor
public class UserContextFilter extends OncePerRequestFilter {

  public static final String USER_ID_HEADER = "X-User-Id";
  public static final String USER_ROLE_HEADER = "X-User-Role";
  public static final String USER_ID_KEY = "userId";

  private final @Nullable Tracer tracer;

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
              : List.<SimpleGrantedAuthority>of();

      var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      if (tracer != null) {
        try (var _ = tracer.createBaggageInScope(USER_ID_KEY, userId)) {
          filterChain.doFilter(request, response);
          return;
        }
      }
    }

    filterChain.doFilter(request, response);
  }
}
