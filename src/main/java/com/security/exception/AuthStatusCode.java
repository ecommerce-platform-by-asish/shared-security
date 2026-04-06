package com.security.exception;

import com.common.exception.StatusCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

/** Error codes specifically for security and authentication failures. */
@Getter
@RequiredArgsConstructor
public enum AuthStatusCode implements StatusCode {
  UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Invalid email or password"),
  FORBIDDEN(HttpStatus.FORBIDDEN, "You do not have permission to access this resource");

  private final HttpStatus status;
  private final String message;
}
