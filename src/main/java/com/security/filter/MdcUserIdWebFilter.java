package com.security.filter;

import io.micrometer.tracing.Tracer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/** Reactive equivalent of MdcUserIdFilter using Baggage for MDC synchronization. */
@Slf4j
@NullMarked
@RequiredArgsConstructor
public class MdcUserIdWebFilter implements WebFilter {

  private final @Nullable Tracer tracer;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return ReactiveSecurityContextHolder.getContext()
        .filter(ctx -> ctx.getAuthentication() != null && ctx.getAuthentication().isAuthenticated())
        .doOnNext(
            ctx -> {
              Authentication auth = ctx.getAuthentication();
              if (tracer != null && auth != null && auth.getPrincipal() instanceof String userId) {
                try (var _ = tracer.createBaggageInScope("userId", userId)) {
                  log.debug("Found authenticated user: {}. Seeded baggage in scope.", userId);
                }
              }
            })
        .then(chain.filter(exchange));
  }
}
