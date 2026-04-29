package com.app.security.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/** Consolidated security rules and annotations. */
public interface SecurityRules {

  /** Restricts access to users with ADMIN role. */
  @Target({ElementType.METHOD, ElementType.TYPE})
  @Retention(RetentionPolicy.RUNTIME)
  @PreAuthorize("hasRole('ADMIN')")
  @interface IsAdmin {}

  /** Restricts access to users with USER role. */
  @Target({ElementType.METHOD, ElementType.TYPE})
  @Retention(RetentionPolicy.RUNTIME)
  @PreAuthorize("hasRole('USER')")
  @interface IsUser {}

  /** Bypasses security authentication checks for the annotated endpoint. */
  @Target({ElementType.METHOD, ElementType.TYPE})
  @Retention(RetentionPolicy.RUNTIME)
  @Documented
  @interface PublicEndpoint {}
}
