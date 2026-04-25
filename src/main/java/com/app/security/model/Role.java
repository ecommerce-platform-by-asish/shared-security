package com.app.security.model;

/** Standard user roles for the platform. */
public enum Role {
  ADMIN,
  USER,
  GUEST;

  public String getAuthority() {
    return SecurityConstants.ROLE_PREFIX + name();
  }
}
