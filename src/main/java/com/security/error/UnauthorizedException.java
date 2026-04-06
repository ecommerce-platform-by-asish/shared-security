package com.security.error;

import com.common.error.BaseException;

/** Exception thrown when authentication fails. */
public class UnauthorizedException extends BaseException {

  public UnauthorizedException() {
    super(AuthErrorCode.UNAUTHORIZED);
  }

  public UnauthorizedException(String message) {
    super(message, AuthErrorCode.UNAUTHORIZED);
  }
}
