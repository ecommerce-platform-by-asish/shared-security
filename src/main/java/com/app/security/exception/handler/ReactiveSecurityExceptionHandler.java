package com.app.security.exception.handler;

import com.app.common.dto.ApiResponse;
import com.app.security.exception.AuthStatusCode;
import com.app.security.exception.UnauthorizedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** Handles security-related exceptions for Reactive (WebFlux) applications. */
@Slf4j
@Order(-1)
@ControllerAdvice
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
public class ReactiveSecurityExceptionHandler {

  @ExceptionHandler(UnauthorizedException.class)
  public Mono<ResponseEntity<ApiResponse<Void>>> handleUnauthorizedException(
      UnauthorizedException ex, ServerWebExchange exchange) {
    log.warn(
        "Unauthorized access at path: {}: {}", exchange.getRequest().getPath(), ex.getMessage());
    return Mono.just(
        ResponseEntity.status(ex.getStatusCode())
            .body(ApiResponse.error(ex.getErrorCode(), ex.getMessage())));
  }

  @ExceptionHandler(AccessDeniedException.class)
  public Mono<ResponseEntity<ApiResponse<Void>>> handleAccessDeniedException(
      AccessDeniedException ex, ServerWebExchange exchange) {
    log.warn("Access denied at path: {}", exchange.getRequest().getPath());
    return Mono.just(
        ResponseEntity.status(HttpStatus.FORBIDDEN)
            .body(ApiResponse.error(AuthStatusCode.FORBIDDEN)));
  }
}
