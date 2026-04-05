package com.ecommerce.security.gateway;

import lombok.Data;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Shared Gateway Filter for JWT authentication, Coarse-Grained Authorization, and Header
 * Propagation.
 *
 * <p>Validates the Bearer token using OAuth2 Resource Server's ReactiveJwtDecoder, optionally
 * verifies required roles at the edge, and propagates user identity claims as downstream headers.
 */
public class AuthenticationFilter
    extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

  private final ReactiveJwtDecoder jwtDecoder;

  public AuthenticationFilter(ReactiveJwtDecoder jwtDecoder) {
    super(Config.class);
    this.jwtDecoder = jwtDecoder;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

      if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        return onError(
            exchange, "Missing or Invalid Authorization Header", HttpStatus.UNAUTHORIZED);
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
                    return onError(
                        exchange, "Insufficient permissions for this route.", HttpStatus.FORBIDDEN);
                  }
                }

                ServerHttpRequest request =
                    exchange
                        .getRequest()
                        .mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Role", role)
                        .build();

                return chain.filter(exchange.mutate().request(request).build());
              })
          .onErrorResume(e -> onError(exchange, "Invalid Token", HttpStatus.UNAUTHORIZED));
    };
  }

  private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
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
