package com.ecommerce.security.user;

public enum Role {
  ADMIN,
  USER,
  GUEST;

  public String getAuthority() {
    return "ROLE_" + name();
  }
}
