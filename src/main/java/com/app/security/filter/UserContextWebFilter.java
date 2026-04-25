package com.app.security.filter;

import com.app.security.model.SecurityConstants;
import io.micrometer.tracing.Tracer;
import java.util.Arrays;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/** Reactive WebFilter that populates SecurityContext from user identity headers. */
@RequiredArgsConstructor
public class UserContextWebFilter implements WebFilter {

  private final @Nullable Tracer tracer;

  @Override
  @NonNull
  public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
    String userId = exchange.getRequest().getHeaders().getFirst(SecurityConstants.USER_ID_HEADER);
    String role = exchange.getRequest().getHeaders().getFirst(SecurityConstants.USER_ROLE_HEADER);

    if (userId == null) {
      return chain.filter(exchange);
    }

    var authorities =
        Stream.ofNullable(role)
            .flatMap(r -> Arrays.stream(r.split(",")))
            .map(String::trim)
            .map(String::toUpperCase)
            .map(
                r ->
                    r.startsWith(SecurityConstants.ROLE_PREFIX)
                        ? r
                        : SecurityConstants.ROLE_PREFIX + r)
            .map(SimpleGrantedAuthority::new)
            .toList();

    var auth = new UsernamePasswordAuthenticationToken(userId, null, authorities);

    return chain
        .filter(exchange)
        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
        .doOnSubscribe(
            _ -> {
              if (tracer != null) {
                var baggage = tracer.getBaggage(SecurityConstants.USER_ID_KEY);
                baggage.makeCurrent(userId).close();
              }
            });
  }
}
