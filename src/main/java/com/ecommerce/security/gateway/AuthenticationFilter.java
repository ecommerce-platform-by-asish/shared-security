package com.ecommerce.security.gateway;

import com.ecommerce.security.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import lombok.Data;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Shared Gateway Filter for JWT authentication.
 *
 * <p>Validates the Bearer token in the Authorization header and propagates user identity claims as
 * downstream headers (X-User-Id and X-User-Role).
 */
public class AuthenticationFilter
    extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

  private final JwtProvider jwtProvider;

  public AuthenticationFilter(JwtProvider jwtProvider) {
    super(Config.class);
    this.jwtProvider = jwtProvider;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
      if (authHeader == null) {
        return onError(exchange, "Missing Authorization Header", HttpStatus.UNAUTHORIZED);
      }

      if (authHeader.startsWith("Bearer ")) {
        authHeader = authHeader.substring(7);
      } else {
        return onError(exchange, "Invalid Authorization Header", HttpStatus.UNAUTHORIZED);
      }

      try {
        Claims claims = jwtProvider.validateToken(authHeader);
        String userId = claims.get("id", String.class);
        String role = claims.get("role", String.class);

        ServerHttpRequest request =
            exchange
                .getRequest()
                .mutate()
                .header("X-User-Id", userId)
                .header("X-User-Role", role)
                .build();

        return chain.filter(exchange.mutate().request(request).build());
      } catch (Exception e) {
        return onError(exchange, "Invalid Token", HttpStatus.UNAUTHORIZED);
      }
    };
  }

  private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
    var response = exchange.getResponse();
    response.setStatusCode(httpStatus);
    return response.setComplete();
  }

  @Data
  public static class Config {
    // Add configuration properties if needed
  }
}
