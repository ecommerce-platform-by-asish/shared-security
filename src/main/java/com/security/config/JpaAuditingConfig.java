package com.security.config;

import com.security.audit.AuditorAwareImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/** Shared JPA auditing configuration that safely handles non-JPA environments. */
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
