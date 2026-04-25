package com.app.security.exception;

import com.app.common.exception.BaseException;

public class KeyPairNotInitializedException extends BaseException {

  public KeyPairNotInitializedException(String operation) {
    super(
        "RSA KeyPair is not initialized for %s tokens.".formatted(operation),
        AuthStatusCode.KEY_PAIR_NOT_INITIALIZED);
  }
}
