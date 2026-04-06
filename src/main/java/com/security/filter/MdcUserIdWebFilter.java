package com.security.filter;

import org.slf4j.MDC;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/** Reactive equivalent of MdcUserIdFilter for WebFlux and Gateway apps. */
public class MdcUserIdWebFilter implements WebFilter {

  public static final String MDC_USER_ID_KEY = "userId";

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .filter(auth -> auth != null && auth.isAuthenticated())
        .filter(auth -> auth.getPrincipal() instanceof String)
        .doOnNext(auth -> MDC.put(MDC_USER_ID_KEY, (String) auth.getPrincipal()))
        .then(chain.filter(exchange))
        .doFinally(signal -> MDC.remove(MDC_USER_ID_KEY));
  }
}
