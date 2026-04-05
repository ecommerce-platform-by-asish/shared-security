package com.ecommerce.security.exception;

import com.ecommerce.common.exception.BaseException;

/**
 * Exception thrown when authentication fails. Uses HttpStatus.UNAUTHORIZED and
 * GlobalErrorCode.UNAUTHORIZED.
 */
public class UnauthorizedException extends BaseException {

  public UnauthorizedException() {
    super(AuthErrorCode.UNAUTHORIZED);
  }

  public UnauthorizedException(String message) {
    super(message, AuthErrorCode.UNAUTHORIZED);
  }
}
