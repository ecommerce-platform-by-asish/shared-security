package com.ecommerce.security.config;

import com.ecommerce.security.gateway.AuthenticationFilter;
import com.ecommerce.security.jwt.JwtProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Main auto-configuration class for the shared-security library.
 *
 * <p>This class bootstraps common beans (like the JwtProvider) and conditionally imports the
 * appropriate security configuration (Servlet or Reactive) based on the application type.
 */
@Configuration
public class SecurityAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JwtProvider jwtProvider() {
    return new JwtProvider();
  }

  @Bean
  @ConditionalOnMissingBean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /**
   * Only loads if the Servlet API is present. This allows the library to be used in non-web
   * applications without crashing.
   */
  @Configuration
  @ConditionalOnClass(name = "jakarta.servlet.DispatcherType")
  @Import(WebSecurityAutoConfiguration.class)
  static class WebSecurityImportConfig {}

  /** Only loads if the Reactive (WebFlux) API is present. */
  @Configuration
  @ConditionalOnClass(name = "org.springframework.web.reactive.DispatcherHandler")
  @Import(WebSecurityAutoConfiguration.class)
  static class ReactiveSecurityImportConfig {}

  /** Loads Gateway-specific security components if the Spring Cloud Gateway API is present. */
  @Configuration
  @ConditionalOnClass(
      name = "org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory")
  static class GatewaySecurityConfig {

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationFilter authenticationFilter(JwtProvider jwtProvider) {
      return new AuthenticationFilter(jwtProvider);
    }
  }
}
