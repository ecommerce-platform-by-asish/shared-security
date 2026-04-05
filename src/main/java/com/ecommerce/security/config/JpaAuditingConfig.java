package com.ecommerce.security.config;

import com.ecommerce.security.audit.AuditorAwareImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * Shared JPA auditing configuration.
 *
 * <p>Uses a double-guarded nested configuration to ensure no JPA-specific annotations from Spring
 * Data JPA are processed in non-JPA environments like the api-gateway.
 */
@Configuration
@ConditionalOnClass(name = "org.springframework.data.jpa.repository.config.EnableJpaAuditing")
public class JpaAuditingConfig {

  @Configuration
  @EnableJpaAuditing(auditorAwareRef = "auditorProvider")
  public static class JpaAuditingEnableConfig {

    @Bean
    public AuditorAware<String> auditorProvider() {
      return new AuditorAwareImpl();
    }
  }
}
