package com.ecommerce.security.config;

import com.ecommerce.security.gateway.AuthenticationFilter;
import com.ecommerce.security.jwt.JwtProvider;
import com.ecommerce.security.jwt.RedisTokenBlacklistManager;
import java.security.KeyPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Main entry point for the security library. Automatically sets up JWT, Password hashing, and
 * environment-specific security rules.
 */
@Configuration
public class SecurityAutoConfiguration {

  /** Creates the component for token generation and verification. */
  @Bean
  @ConditionalOnMissingBean
  public JwtProvider jwtProvider(@Autowired(required = false) KeyPair keyPair) {
    return new JwtProvider(keyPair);
  }

  /** Sets BCrypt as the standard password hashing algorithm. */
  @Bean
  @ConditionalOnMissingBean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /** Conditionally loads Servlet-based security configuration. */
  @Configuration
  @ConditionalOnClass(name = "jakarta.servlet.DispatcherType")
  @Import(WebSecurityAutoConfiguration.class)
  static class WebSecurityImportConfig {}

  /** Conditionally loads Reactive (WebFlux) security configuration. */
  @Configuration
  @ConditionalOnClass(name = "org.springframework.web.reactive.DispatcherHandler")
  @Import(WebSecurityAutoConfiguration.class)
  static class ReactiveSecurityImportConfig {}

  /** Conditionally loads Gateway-specific security components. */
  @Configuration
  @ConditionalOnClass(
      name = "org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory")
  static class GatewaySecurityConfig {

    @Bean
    @ConditionalOnMissingBean
    public AuthenticationFilter authenticationFilter(
        ReactiveJwtDecoder jwtDecoder,
        @Autowired(required = false) RedisTokenBlacklistManager blacklistManager) {
      return new AuthenticationFilter(jwtDecoder, blacklistManager);
    }
  }

  @Configuration
  @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisOperations")
  static class TokenBlacklistAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(RedisTokenBlacklistManager.class)
    public RedisTokenBlacklistManager tokenBlacklistManager(
        @Autowired(required = false) StringRedisTemplate blockingTemplate,
        @Autowired(required = false) ReactiveStringRedisTemplate reactiveTemplate) {
      return new RedisTokenBlacklistManager(blockingTemplate, reactiveTemplate);
    }
  }
}
