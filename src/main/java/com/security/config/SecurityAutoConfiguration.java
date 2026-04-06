package com.security.config;

import com.security.filter.MdcUserIdFilter;
import com.security.filter.MdcUserIdWebFilter;
import com.security.gateway.AuthenticationFilter;
import com.security.jwt.JwtProvider;
import com.security.jwt.RedisTokenBlacklistManager;
import java.security.KeyPair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Core security auto-configuration providing JWT support, password encoding, and logging filters.
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
  static class WebSecurityImportConfig {

    /** Seeds userId into SLF4J MDC for every Servlet request. */
    @Bean
    @ConditionalOnMissingBean
    public FilterRegistrationBean<MdcUserIdFilter> mdcUserIdFilterRegistration(
        io.micrometer.tracing.Tracer tracer) {
      FilterRegistrationBean<MdcUserIdFilter> registration = new FilterRegistrationBean<>();
      registration.setFilter(new MdcUserIdFilter(tracer));
      registration.addUrlPatterns("/*");
      // Run after Spring Security (order ~100) so SecurityContext is already populated
      registration.setOrder(org.springframework.core.Ordered.LOWEST_PRECEDENCE - 10);
      registration.setName("mdcUserIdFilter");
      return registration;
    }
  }

  /** Conditionally loads Reactive (WebFlux) security configuration. */
  @Configuration
  @ConditionalOnClass(name = "org.springframework.web.reactive.DispatcherHandler")
  @Import(WebSecurityAutoConfiguration.class)
  static class ReactiveSecurityImportConfig {

    /** Seeds userId into SLF4J MDC for every reactive request. */
    @Bean
    @ConditionalOnMissingBean
    public MdcUserIdWebFilter mdcUserIdWebFilter(io.micrometer.tracing.Tracer tracer) {
      return new MdcUserIdWebFilter(tracer);
    }
  }

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
