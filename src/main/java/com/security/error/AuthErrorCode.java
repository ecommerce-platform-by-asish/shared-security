package com.security.error;

import com.common.error.ErrorCode;
import lombok.Getter;
import org.springframework.http.HttpStatus;

/** Error codes specifically for security and authentication failures. */
@Getter
public enum AuthErrorCode implements ErrorCode {
  UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Invalid email or password"),
  FORBIDDEN(HttpStatus.FORBIDDEN, "You do not have permission to access this resource");

  private final HttpStatus status;
  private final String message;

  AuthErrorCode(HttpStatus status, String message) {
    this.status = status;
    this.message = message;
  }
}
