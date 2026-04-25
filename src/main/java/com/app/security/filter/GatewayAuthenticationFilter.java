package com.app.security.filter;

import com.app.security.model.SecurityConstants;
import com.app.security.token.RedisTokenBlacklistManager;
import io.micrometer.tracing.Tracer;
import java.util.Collections;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** Gateway security filter for JWT validation and identity propagation. */
@Slf4j
public class GatewayAuthenticationFilter
    extends AbstractGatewayFilterFactory<GatewayAuthenticationFilter.Config> {

  private final ReactiveJwtDecoder jwtDecoder;
  private final RedisTokenBlacklistManager blacklistManager;

  public GatewayAuthenticationFilter(
      ReactiveJwtDecoder jwtDecoder,
      @Autowired(required = false) RedisTokenBlacklistManager blacklistManager) {
    super(Config.class);
    this.jwtDecoder = jwtDecoder;
    this.blacklistManager = blacklistManager;
  }

  @Override
  public String name() {
    return "GatewayAuthentication";
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      log.debug(
          "GatewayAuthenticationFilter: Processing request to {}", exchange.getRequest().getPath());
      String authHeader =
          exchange.getRequest().getHeaders().getFirst(SecurityConstants.AUTHORIZATION_HEADER);

      if (authHeader == null || !authHeader.startsWith(SecurityConstants.BEARER_PREFIX)) {
        return chain.filter(exchange);
      }

      String token = authHeader.substring(SecurityConstants.BEARER_PREFIX.length());

      return jwtDecoder
          .decode(token)
          .flatMap(
              jwt -> {
                String userId = jwt.getClaimAsString(SecurityConstants.CLAIM_USER_ID);
                String role = jwt.getClaimAsString(SecurityConstants.CLAIM_ROLE);
                log.info(
                    "GatewayAuthenticationFilter: Decoded JWT for user: {}, role: {}",
                    userId,
                    role);

                // Coarse-grained Authorization at the Edge
                if (config.getRequiredRole() != null && !config.getRequiredRole().isBlank()) {
                  if (role == null || !role.equalsIgnoreCase(config.getRequiredRole())) {
                    return onError(exchange, HttpStatus.FORBIDDEN);
                  }
                }

                // Redis Revocation Check
                Mono<Void> processRequest =
                    Mono.defer(
                        () -> {
                          ServerHttpRequest request =
                              exchange
                                  .getRequest()
                                  .mutate()
                                  .header(SecurityConstants.USER_ID_HEADER, userId)
                                  .header(SecurityConstants.USER_ROLE_HEADER, role)
                                  .build();
                          return chain.filter(exchange.mutate().request(request).build());
                        });

                Mono<Void> authenticatedFlow;
                if (blacklistManager != null) {
                  authenticatedFlow =
                      blacklistManager
                          .isBlacklistedReactive(jwt.getId())
                          .flatMap(
                              isBlacklisted -> {
                                if (isBlacklisted) {
                                  return onError(exchange, HttpStatus.UNAUTHORIZED);
                                }
                                return processRequest;
                              });
                } else {
                  authenticatedFlow = processRequest;
                }

                // Seed userId into tracing baggage
                return Mono.deferContextual(
                        ctx -> {
                          if (ctx.hasKey(Tracer.class)) {
                            Tracer tracer = ctx.get(Tracer.class);
                            var baggage = tracer.getBaggage(SecurityConstants.USER_ID_KEY);
                            baggage.makeCurrent(userId).close();
                          }

                          Authentication auth =
                              new UsernamePasswordAuthenticationToken(
                                  userId,
                                  null,
                                  Collections.singletonList(
                                      new SimpleGrantedAuthority(
                                          SecurityConstants.ROLE_PREFIX + role.toUpperCase())));

                          return authenticatedFlow.contextWrite(
                              ReactiveSecurityContextHolder.withAuthentication(auth));
                        })
                    .onErrorResume(_ -> onError(exchange, HttpStatus.UNAUTHORIZED));
              })
          .onErrorResume(_ -> onError(exchange, HttpStatus.UNAUTHORIZED));
    };
  }

  private Mono<Void> onError(
      @NonNull ServerWebExchange exchange, @NonNull HttpStatusCode httpStatus) {
    var response = exchange.getResponse();
    response.setStatusCode(httpStatus);
    return response.setComplete();
  }

  @Data
  public static class Config {
    /**
     * Optional role required to access the route. If specified, the filter will verify that the
     * role claim in the JWT matches this value (case-insensitive).
     */
    private String requiredRole;
  }
}
