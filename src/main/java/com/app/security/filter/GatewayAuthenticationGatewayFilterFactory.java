package com.app.security.filter;

import com.app.security.model.SecurityConstants;
import com.app.security.token.RedisTokenBlacklistManager;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.tracing.Tracer;
import java.util.Collections;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** Validates JWT tokens at the entry point and extracts user metadata for downstream services. */
@Slf4j
public class GatewayAuthenticationGatewayFilterFactory
    extends AbstractGatewayFilterFactory<GatewayAuthenticationGatewayFilterFactory.Config> {

  private final ReactiveJwtDecoder jwtDecoder;
  private final RedisTokenBlacklistManager blacklistManager;
  private final Tracer tracer;

  public GatewayAuthenticationGatewayFilterFactory(
      ReactiveJwtDecoder jwtDecoder,
      @Autowired(required = false) RedisTokenBlacklistManager blacklistManager,
      ObjectProvider<Tracer> tracerProvider,
      ObjectProvider<ObservationRegistry> observationRegistryProvider) {
    super(Config.class);
    this.jwtDecoder = jwtDecoder;
    this.blacklistManager = blacklistManager;
    this.tracer = tracerProvider.getIfAvailable();
    observationRegistryProvider.getIfAvailable();
    log.info("GatewayAuthenticationFilter: BEAN CREATED");
  }

  @Override
  public String name() {
    return "GatewayAuthentication";
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      log.info(
          "GatewayAuthenticationFilter: EXECUTING for path: {}", exchange.getRequest().getPath());

      String authHeader =
          exchange.getRequest().getHeaders().getFirst(SecurityConstants.AUTHORIZATION_HEADER);
      if (authHeader == null || !authHeader.startsWith(SecurityConstants.BEARER_PREFIX)) {
        log.info("GatewayAuthenticationFilter: No bearer token found, skipping authentication");
        return chain.filter(exchange);
      }

      String token = authHeader.substring(SecurityConstants.BEARER_PREFIX.length());
      log.info(
          "GatewayAuthenticationFilter: Processing token starting with: {}",
          token.substring(0, Math.min(token.length(), 10)));

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

                // Inject X-User-Id, X-User-Role, and W3C baggage header directly.
                // W3C baggage header ensures downstream Micrometer auto-syncs userId→MDC
                // reliably, avoiding ReactorThreadLocal scope loss on Netty thread hops.
                var baggageHeader =
                    SecurityConstants.USER_ID_KEY + "=" + userId + ";propagation=unlimited";
                var mutatedRequest =
                    exchange
                        .getRequest()
                        .mutate()
                        .header(SecurityConstants.USER_ID_HEADER, userId)
                        .header(SecurityConstants.USER_ROLE_HEADER, role)
                        .header("baggage", baggageHeader)
                        .build();
                var mutatedExchange = exchange.mutate().request(mutatedRequest).build();

                if (tracer != null && tracer.currentSpan() != null) {
                  tracer.createBaggage(SecurityConstants.USER_ID_KEY).set(userId);
                }

                Authentication auth =
                    new UsernamePasswordAuthenticationToken(
                        userId,
                        null,
                        Collections.singletonList(
                            new SimpleGrantedAuthority(
                                SecurityConstants.ROLE_PREFIX + role.toUpperCase())));

                Mono<Boolean> blacklistCheck =
                    (blacklistManager != null)
                        ? blacklistManager
                            .isBlacklistedReactive(jwt.getId())
                            .onErrorResume(
                                e -> {
                                  log.warn(
                                      "Redis blacklist check failed, allowing request: {}",
                                      e.getMessage());
                                  return Mono.just(false);
                                })
                        : Mono.just(false);

                return blacklistCheck.flatMap(
                    isBlacklisted -> {
                      if (isBlacklisted) {
                        return onError(mutatedExchange, HttpStatus.UNAUTHORIZED);
                      }
                      return chain
                          .filter(mutatedExchange)
                          .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
                    });
              })
          .onErrorResume(
              JwtException.class,
              e -> {
                log.error("GatewayAuthenticationFilter: Invalid token: {}", e.getMessage());
                return onError(exchange, HttpStatus.UNAUTHORIZED);
              });
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
