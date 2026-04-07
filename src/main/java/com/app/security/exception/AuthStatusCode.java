package com.app.security.exception;

import com.app.common.exception.StatusCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

/** Error codes specifically for security and authentication failures. */
@Getter
@RequiredArgsConstructor
public enum AuthStatusCode implements StatusCode {
  UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Invalid email or password"),
  FORBIDDEN(HttpStatus.FORBIDDEN, "You do not have permission to access this resource");

  private final HttpStatusCode status;
  private final String message;
}
