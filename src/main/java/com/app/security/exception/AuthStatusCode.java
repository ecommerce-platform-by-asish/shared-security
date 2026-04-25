package com.app.security.exception;

import com.app.common.exception.StatusCode;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

public enum AuthStatusCode implements StatusCode {
  UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "Invalid email or password"),
  FORBIDDEN(HttpStatus.FORBIDDEN, "You do not have permission to access this resource"),
  KEY_PAIR_NOT_INITIALIZED(HttpStatus.INTERNAL_SERVER_ERROR, "RSA key pair is not configured");

  private final HttpStatusCode status;
  private final String message;

  AuthStatusCode(HttpStatusCode status, String message) {
    this.status = status;
    this.message = message;
  }

  @Override
  public HttpStatusCode getStatus() {
    return status;
  }

  @Override
  public String getMessage() {
    return message;
  }
}
