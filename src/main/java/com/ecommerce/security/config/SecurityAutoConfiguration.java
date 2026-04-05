package com.ecommerce.security.config;

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
 * <p>This class bootstraps both common beans (like the JWT Validator) and web-specific security
 * (like the UserContextFilter) when the library is detected on the classpath.
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
}
