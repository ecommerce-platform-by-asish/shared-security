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
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/** Holder for Security Exception Handlers that provide standardized error responses. */
public final class SecurityExceptionHandler {

  private SecurityExceptionHandler() {}

  /** Intercepts security-specific exceptions in Servlet apps. */
  @Slf4j
  @Order(-1)
  @ControllerAdvice
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  public static class Servlet {

    /** Handles explicit unauthorized business exceptions. */
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ApiResponse<Void>> handleUnauthorizedException(
        UnauthorizedException ex, WebRequest request) {
      log.warn("Unauthorized access at path: {}: {}", request.getContextPath(), ex.getMessage());
      return ResponseEntity.status(ex.getStatusCode())
          .body(ApiResponse.error(ex.getErrorCode(), ex.getMessage()));
    }

    /** Maps Spring Security AccessDeniedException to a 403 Forbidden response. */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<Void>> handleAccessDeniedException(
        AccessDeniedException ex, WebRequest request) {
      log.warn("Access denied at path: {}", request.getContextPath());
      return ResponseEntity.status(HttpStatus.FORBIDDEN)
          .body(ApiResponse.error(AuthStatusCode.FORBIDDEN));
    }
  }

  /** Intercepts security-specific exceptions in Reactive apps. */
  @Slf4j
  @Order(-1)
  @ControllerAdvice
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
  public static class Reactive {

    /** Handles explicit unauthorized business exceptions in a reactive flow. */
    @ExceptionHandler(UnauthorizedException.class)
    public Mono<ResponseEntity<ApiResponse<Void>>> handleUnauthorizedException(
        UnauthorizedException ex, ServerWebExchange exchange) {
      log.warn(
          "Unauthorized access at path: {}: {}", exchange.getRequest().getPath(), ex.getMessage());
      return Mono.just(
          ResponseEntity.status(ex.getStatusCode())
              .body(ApiResponse.error(ex.getErrorCode(), ex.getMessage())));
    }

    /** Maps Reactive AccessDeniedException to a 403 Forbidden response. */
    @ExceptionHandler(AccessDeniedException.class)
    public Mono<ResponseEntity<ApiResponse<Void>>> handleAccessDeniedException(
        AccessDeniedException ex, ServerWebExchange exchange) {
      log.warn("Access denied at path: {}", exchange.getRequest().getPath());
      return Mono.just(
          ResponseEntity.status(HttpStatus.FORBIDDEN)
              .body(ApiResponse.error(AuthStatusCode.FORBIDDEN)));
    }
  }
}
