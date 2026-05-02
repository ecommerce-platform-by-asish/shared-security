package com.app.security.configuration;

import com.app.security.model.SecurityConstants;
import com.app.security.util.SecurityUtils;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.domain.ReactiveAuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Auto-configures Spring Data Auditing (e.g., @CreatedBy, @LastModifiedBy) by extracting the
 * current user securely from the Security Context.
 */
@Configuration(proxyBeanMethods = false)
public class JpaAuditingConfiguration {

  // Logic moved to SecurityUtils.resolveUserId

  /** Configuration for standard Servlet/Blocking applications. */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnWebApplication(type = Type.SERVLET)
  @ConditionalOnClass(EnableJpaAuditing.class)
  @EnableJpaAuditing(auditorAwareRef = "auditorProvider")
  public static class ServletAuditingConfig {

    @Bean
    @ConditionalOnMissingBean
    public AuditorAware<String> auditorProvider() {
      return () ->
          Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
              .map(SecurityUtils::resolveUserId);
    }
  }

  /** Configuration for fully Reactive applications. */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnWebApplication(type = Type.REACTIVE)
  @ConditionalOnClass(ReactiveAuditorAware.class)
  public static class ReactiveAuditingConfig {

    @Bean
    @ConditionalOnMissingBean
    public ReactiveAuditorAware<String> reactiveAuditorProvider() {
      return () ->
          ReactiveSecurityContextHolder.getContext()
              .mapNotNull(SecurityContext::getAuthentication)
              .map(SecurityUtils::resolveUserId)
              .defaultIfEmpty(SecurityConstants.ANONYMOUS_USER);
    }
  }
}
