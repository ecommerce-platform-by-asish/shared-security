package com.app.security.exception;

import com.app.common.exception.BaseException;
import com.app.common.exception.GlobalStatusCode;
import java.io.Serial;

/**
 * Exception thrown when RSA key operations fail. Uses HttpStatus.INTERNAL_SERVER_ERROR and
 * GlobalStatusCode.INTERNAL_SERVER_ERROR.
 */
public class RsaException extends BaseException {

  @Serial private static final long serialVersionUID = 1L;

  public RsaException(String message, Throwable cause) {
    super(message, GlobalStatusCode.INTERNAL_SERVER_ERROR, cause);
  }
}
