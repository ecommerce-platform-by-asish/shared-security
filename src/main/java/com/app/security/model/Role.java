package com.app.security.model;

/** Standard user roles for the platform. */
public enum Role {
  ADMIN,
  USER,
  GUEST;

  /** Returns the Spring Security compliant role string (e.g., ROLE_USER). */
  public String getAuthority() {
    return SecurityConstants.ROLE_PREFIX + name();
  }
}
