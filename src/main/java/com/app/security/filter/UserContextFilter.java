package com.app.security.filter;

import com.app.security.model.SecurityConstants;
import io.micrometer.tracing.Tracer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.MDC;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/** Holder for User Identity filters that propagate Gateway headers into Security Contexts. */
public final class UserContextFilter {

  private UserContextFilter() {}

  /** Propagates user identity into the Servlet Security Context and MDC. */
  @Slf4j
  @RequiredArgsConstructor
  public static class Servlet extends OncePerRequestFilter {
    private final @Nullable Tracer tracer;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain)
        throws ServletException, IOException {
      String userId = request.getHeader(SecurityConstants.USER_ID_HEADER);

      String effectiveUserId = userId != null ? userId : SecurityConstants.ANONYMOUS_USER;

      if (userId != null) {
        String role = request.getHeader(SecurityConstants.USER_ROLE_HEADER);
        var authorities =
            Stream.ofNullable(role)
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
        var auth = new UsernamePasswordAuthenticationToken(userId, null, authorities);
        SecurityContextHolder.getContext().setAuthentication(auth);
      }

      // MDC.putCloseable covers this filter's own log lines.
      // tracer.createBaggage.makeCurrent ensures sub-observations (DispatcherServlet, JPA, etc.)
      // also read userId=effectiveUserId from Baggage when syncing correlation fields to MDC.
      try (var mdcScope = MDC.putCloseable(SecurityConstants.USER_ID_KEY, effectiveUserId)) {
        if (tracer != null) {
          try (var baggageScope =
              tracer.createBaggage(SecurityConstants.USER_ID_KEY).makeCurrent(effectiveUserId)) {
            filterChain.doFilter(request, response);
          }
        } else {
          filterChain.doFilter(request, response);
        }
      }
    }
  }

  /** Propagates user identity into the Reactive Security Context and MDC. */
  @RequiredArgsConstructor
  public static class Reactive implements WebFilter {
    private final @Nullable Tracer tracer;

    /** Extracts identity from headers and populates the reactive context. */
    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
      String userId = exchange.getRequest().getHeaders().getFirst(SecurityConstants.USER_ID_HEADER);
      String effectiveUserId = userId != null ? userId : SecurityConstants.ANONYMOUS_USER;

      var flow =
          chain
              .filter(exchange)
              .doFirst(() -> MDC.put(SecurityConstants.USER_ID_KEY, effectiveUserId))
              .doFinally(_ -> MDC.remove(SecurityConstants.USER_ID_KEY));

      if (userId == null) {
        return flow;
      }

      String role = exchange.getRequest().getHeaders().getFirst(SecurityConstants.USER_ROLE_HEADER);
      var authorities =
          Stream.ofNullable(role)
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

      var auth = new UsernamePasswordAuthenticationToken(userId, null, authorities);
      return flow.contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
    }
  }
}
