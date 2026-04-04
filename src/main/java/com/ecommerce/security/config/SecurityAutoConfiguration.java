package com.ecommerce.security.config;

import com.ecommerce.security.jwt.JwtTokenValidator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Main auto-configuration class for the shared-security library.
 *
 * <p>This class bootstraps both common beans (like the JWT Validator) and web-specific security
 * (like the UserContextFilter) when the library is detected on the classpath.
 */
@Configuration
public class SecurityAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public JwtTokenValidator jwtTokenValidator() {
    return new JwtTokenValidator();
  }

  /**
   * Only loads if the Servlet API is present. This allows the library to be used in non-web
   * applications without crashing.
   */
  @Configuration
  @ConditionalOnClass(name = "jakarta.servlet.DispatcherType")
  @Import(WebSecurityAutoConfiguration.class)
  static class WebSecurityImportConfig {}
}
