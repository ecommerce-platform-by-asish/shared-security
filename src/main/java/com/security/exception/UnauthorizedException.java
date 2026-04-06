package com.security.exception;

import com.common.exception.BaseException;

/** Exception thrown when authentication fails. */
public class UnauthorizedException extends BaseException {

  public UnauthorizedException() {
    super(AuthStatusCode.UNAUTHORIZED);
  }

  public UnauthorizedException(String message) {
    super(message, AuthStatusCode.UNAUTHORIZED);
  }
}
