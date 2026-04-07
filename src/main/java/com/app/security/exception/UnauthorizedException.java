package com.app.security.exception;

import com.app.common.exception.BaseException;
import java.io.Serial;

/** Exception thrown when authentication fails. */
public class UnauthorizedException extends BaseException {

  @Serial private static final long serialVersionUID = 1L;

  public UnauthorizedException() {
    super(AuthStatusCode.UNAUTHORIZED);
  }

  public UnauthorizedException(String message) {
    super(message, AuthStatusCode.UNAUTHORIZED);
  }
}
