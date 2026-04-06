package com.security.audit;

import java.util.Optional;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.context.SecurityContextHolder;

/** Provides the currently authenticated user's ID as the auditor for JPA. */
public class AuditorAwareImpl implements AuditorAware<String> {

  @Override
  public Optional<String> getCurrentAuditor() {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null
        || !authentication.isAuthenticated()
        || authentication.getName() == null) {
      return Optional.of("annonymous");
    }
    return Optional.of(authentication.getName());
  }
}
