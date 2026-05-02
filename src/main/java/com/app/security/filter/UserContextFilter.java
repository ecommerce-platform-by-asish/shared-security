package com.app.security.filter;

import com.app.common.context.UserContext;
import com.app.security.model.SecurityConstants;
import com.app.security.util.SecurityUtils;
import io.micrometer.tracing.BaggageInScope;
import io.micrometer.tracing.Tracer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public final class UserContextFilter {

  private UserContextFilter() {}

  @RequiredArgsConstructor
  public static class Servlet extends OncePerRequestFilter {
    private final @Nullable Tracer tracer;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain) {

      String userId =
          SecurityUtils.resolveUserId(SecurityContextHolder.getContext().getAuthentication());
      String traceId = SecurityUtils.resolveTraceId(tracer);

      UserContext.runWithContext(
          traceId,
          userId,
          () -> {
            if (tracer != null) {
              try (BaggageInScope _ =
                  tracer.createBaggageInScope(SecurityConstants.USER_ID_KEY, userId)) {
                filterChain.doFilter(request, response);
              } catch (ServletException | IOException e) {
                throw new RuntimeException(e);
              }
            } else {
              try {
                filterChain.doFilter(request, response);
              } catch (ServletException | IOException e) {
                throw new RuntimeException(e);
              }
            }
          });
    }
  }

  @RequiredArgsConstructor
  public static class Reactive implements WebFilter {
    private final @Nullable Tracer tracer;

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
      return ReactiveSecurityContextHolder.getContext()
          .mapNotNull(SecurityContext::getAuthentication)
          .map(SecurityUtils::resolveUserId)
          .defaultIfEmpty(SecurityConstants.ANONYMOUS_USER)
          .flatMap(
              userId -> {
                if (tracer != null) {
                  try (var _ = tracer.createBaggageInScope(SecurityConstants.USER_ID_KEY, userId)) {
                    return chain.filter(exchange);
                  }
                }
                return chain.filter(exchange);
              });
    }
  }
}
