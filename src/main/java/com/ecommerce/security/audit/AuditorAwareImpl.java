package com.ecommerce.security.audit;

import java.util.Optional;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Shared JPA auditor aware implementation.
 *
 * <p>This class extracts the authenticated user's ID from the Spring SecurityContext and returns it
 * as the auditor (the person who created or modified a record).
 */
public class AuditorAwareImpl implements AuditorAware<String> {

  @Override
  public Optional<String> getCurrentAuditor() {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication.getName() == null) {
      return Optional.of("system");
    }
    return Optional.of(authentication.getName());
  }
}
