package com.app.security.audit;

import com.app.security.model.SecurityConstants;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.domain.ReactiveAuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Enables shared JPA auditing by automatically extracting the current user from the Security
 * Context.
 */
@Configuration
@ConditionalOnClass(EnableJpaAuditing.class)
public class JpaAuditingConfig {

  @Configuration
  @EnableJpaAuditing(auditorAwareRef = "auditorProvider")
  public static class JpaAuditingEnableConfig {

    /** Provides the current username for auditing in Servlet-based applications. */
    @Bean
    @ConditionalOnWebApplication(type = Type.SERVLET)
    public AuditorAware<String> auditorProvider() {
      return () -> {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null
            || !authentication.isAuthenticated()
            || authentication instanceof AnonymousAuthenticationToken) {
          return Optional.of(SecurityConstants.ANONYMOUS_USER);
        }
        return Optional.of(authentication.getName());
      };
    }

    /** Provides the current username for auditing in Reactive-based applications. */
    @Bean
    @ConditionalOnWebApplication(type = Type.REACTIVE)
    public ReactiveAuditorAware<String> reactiveAuditorProvider() {
      return () ->
          ReactiveSecurityContextHolder.getContext()
              .map(ctx -> ctx.getAuthentication())
              .filter(
                  auth -> auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken))
              .map(auth -> auth.getName())
              .defaultIfEmpty(SecurityConstants.ANONYMOUS_USER);
    }
  }
}
