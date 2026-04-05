package com.ecommerce.security.exception;

import com.ecommerce.common.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@Slf4j
@Order(-1)
@ControllerAdvice
public class SecurityExceptionHandler {

  @ExceptionHandler(UnauthorizedException.class)
  public ResponseEntity<ApiResponse<Void>> handleUnauthorizedException(
      UnauthorizedException ex, HttpServletRequest request) {
    log.warn("Unauthorized access at path: {}: {}", request.getRequestURI(), ex.getMessage());
    return ResponseEntity.status(ex.getHttpStatus())
        .body(ApiResponse.error(ex.getErrorCode(), ex.getMessage()));
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ApiResponse<Void>> handleAccessDeniedException(
      AccessDeniedException ex, HttpServletRequest request) {
    log.warn("Access denied at path: {}", request.getRequestURI());
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
        .body(ApiResponse.error(AuthErrorCode.FORBIDDEN));
  }
}
