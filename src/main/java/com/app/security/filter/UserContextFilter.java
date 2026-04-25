package com.app.security.filter;

import com.app.security.model.SecurityConstants;
import io.micrometer.tracing.Tracer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Populates Spring Security context from incoming user identity headers in Servlet apps. */
@Slf4j
@RequiredArgsConstructor
public class UserContextFilter extends OncePerRequestFilter {

  private final @Nullable Tracer tracer;

  /** Extracts user ID and roles from request headers to set the Spring Security Authentication. */
  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain)
      throws ServletException, IOException {
    String userId = request.getHeader(SecurityConstants.USER_ID_HEADER);
    String role = request.getHeader(SecurityConstants.USER_ROLE_HEADER);

    if (userId != null) {
      log.debug("UserContextFilter: Extracted userId: {}, role: {} from headers", userId, role);

      var authorities =
          role != null
              ? Arrays.stream(role.split(","))
                  .map(String::trim)
                  .map(
                      r ->
                          r.startsWith(SecurityConstants.ROLE_PREFIX)
                              ? r
                              : SecurityConstants.ROLE_PREFIX + r)
                  .map(SimpleGrantedAuthority::new)
                  .toList()
              : List.<SimpleGrantedAuthority>of();

      var authentication = new UsernamePasswordAuthenticationToken(userId, null, authorities);
      SecurityContextHolder.getContext().setAuthentication(authentication);

      if (tracer != null) {
        var baggage = tracer.getBaggage(SecurityConstants.USER_ID_KEY);
        try (var _ = baggage.makeCurrent(userId)) {
          filterChain.doFilter(request, response);
          return;
        }
      }
    }

    filterChain.doFilter(request, response);
  }
}
