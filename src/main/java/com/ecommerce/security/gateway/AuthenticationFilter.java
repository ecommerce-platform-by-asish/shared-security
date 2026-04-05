package com.ecommerce.security.gateway;

import com.ecommerce.security.jwt.TokenBlacklistManager;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Security guard for the Gateway. Validates JWT tokens, checks user roles. Forwards user details to
 * downstream as headers.
 */
public class AuthenticationFilter
    extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

  private final ReactiveJwtDecoder jwtDecoder;
  private final TokenBlacklistManager blacklistManager;

  public AuthenticationFilter(
      ReactiveJwtDecoder jwtDecoder,
      @Autowired(required = false) TokenBlacklistManager blacklistManager) {
    super(Config.class);
    this.jwtDecoder = jwtDecoder;
    this.blacklistManager = blacklistManager;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

      if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        return onError(exchange, HttpStatus.UNAUTHORIZED);
      }

      String token = authHeader.substring(7);

      return jwtDecoder
          .decode(token)
          .flatMap(
              jwt -> {
                String userId = jwt.getClaimAsString("id");
                String role = jwt.getClaimAsString("role");

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
                                  .header("X-User-Id", userId)
                                  .header("X-User-Role", role)
                                  .build();
                          return chain.filter(exchange.mutate().request(request).build());
                        });

                if (blacklistManager != null) {
                  return blacklistManager
                      .isBlacklisted(jwt.getId())
                      .flatMap(
                          isBlacklisted -> {
                            if (isBlacklisted) {
                              return onError(exchange, HttpStatus.UNAUTHORIZED);
                            }
                            return processRequest;
                          });
                }

                return processRequest;
              })
          .onErrorResume(e -> onError(exchange, HttpStatus.UNAUTHORIZED));
    };
  }

  private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
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
