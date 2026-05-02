package com.app.security.model;

/** Security-specific constants for headers, claim keys, and roles. */
public final class SecurityConstants {

  private SecurityConstants() {}

  // Claim Keys
  public static final String CLAIM_USER_ID = "id";
  public static final String CLAIM_ROLE = "role";

  // Propagation Keys
  public static final String USER_ID_KEY = "userId";
  public static final String NONE = "none";

  // Roles & Prefixes
  public static final String ROLE_PREFIX = "ROLE_";
  public static final String ANONYMOUS_USER = "anonymous";

  // Security Headers
  public static final String AUTHORIZATION_HEADER = "Authorization";
  public static final String BEARER_PREFIX = "Bearer ";
  public static final String USER_ID_HEADER = "X-User-Id";
  public static final String USER_ROLE_HEADER = "X-User-Role";

  // Internal Logic
  public static final String ALGORITHM_HMAC_256 = "HmacSHA256";
  public static final String JWT_BLACKLIST = "jwt:blacklist:";
}
