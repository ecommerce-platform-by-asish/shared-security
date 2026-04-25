package com.app.security.model;

public final class SecurityConstants {

  private SecurityConstants() {}

  public static final String AUTHORIZATION_HEADER = "Authorization";
  public static final String USER_ID_HEADER = "X-User-Id";
  public static final String USER_ROLE_HEADER = "X-User-Role";

  public static final String CLAIM_USER_ID = "id";
  public static final String CLAIM_ROLE = "role";

  public static final String USER_ID_KEY = "userId";

  public static final String BEARER_PREFIX = "Bearer ";
  public static final String ROLE_PREFIX = "ROLE_";
  public static final String ANONYMOUS_USER = "anonymous";

  public static final String ALGORITHM_RSA = "RSA";
  public static final String ALGORITHM_HMAC_256 = "HmacSHA256";
}
