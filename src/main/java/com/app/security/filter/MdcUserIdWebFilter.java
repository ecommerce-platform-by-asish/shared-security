package com.app.security.filter;

import io.micrometer.tracing.Tracer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
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
        .map(ctx -> java.util.Optional.ofNullable(ctx.getAuthentication()))
        .defaultIfEmpty(java.util.Optional.empty())
        .flatMap(
            optAuth -> {
              if (optAuth.isPresent()
                  && optAuth.get().isAuthenticated()
                  && tracer != null
                  && optAuth.get().getPrincipal() instanceof String userId) {
                return Mono.using(
                    () -> tracer.createBaggageInScope("userId", userId),
                    _ -> {
                      log.debug("Seeded baggage for authenticated user: {}", userId);
                      return chain.filter(exchange);
                    },
                    io.micrometer.tracing.BaggageInScope::close);
              }
              return chain.filter(exchange);
            });
  }
}
