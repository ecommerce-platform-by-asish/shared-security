package com.security.exception;

import com.common.web.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

/** Handles security-related exceptions and converts them to standardized API responses. */
@Slf4j
@Order(-1)
@ControllerAdvice
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class SecurityExceptionHandler {

  @ExceptionHandler(UnauthorizedException.class)
  public ResponseEntity<ApiResponse<Void>> handleUnauthorizedException(
      UnauthorizedException ex, WebRequest request) {
    log.warn("Unauthorized access at path: {}: {}", request.getContextPath(), ex.getMessage());
    return ResponseEntity.status(ex.getStatusCode())
        .body(ApiResponse.error(ex.getErrorCode(), ex.getMessage()));
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ApiResponse<Void>> handleAccessDeniedException(
      AccessDeniedException ex, WebRequest request) {
    log.warn("Access denied at path: {}", request.getContextPath());
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(ApiResponse.error(AuthStatusCode.FORBIDDEN));
  }
}
