package com.security.user;

/** Standard user roles for the platform. */
public enum Role {
  ADMIN,
  USER,
  GUEST;

  public String getAuthority() {
    return "ROLE_" + name();
  }
}
