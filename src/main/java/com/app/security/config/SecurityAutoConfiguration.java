package com.app.security.config;

import com.app.security.filter.MdcUserIdFilter;
import com.app.security.filter.MdcUserIdWebFilter;
import com.app.security.gateway.AuthenticationFilter;
import com.app.security.jwt.JwtProvider;
import com.app.security.jwt.RedisTokenBlacklistManager;
import io.micrometer.tracing.Tracer;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Core security auto-configuration providing JWT support, password encoding, and logging filters.
 */
@Configuration
@AutoConfigureAfter(
    name =
        "org.springframework.boot.actuate.autoconfigure.tracing.MicrometerTracingAutoConfiguration")
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
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  @ConditionalOnClass(name = "jakarta.servlet.DispatcherType")
  @Import(WebSecurityAutoConfiguration.class)
  static class WebSecurityImportConfig {

    /** Seeds userId into SLF4J MDC for every Servlet request. */
    @Bean
    @ConditionalOnBean(Tracer.class)
    @ConditionalOnMissingBean
    public FilterRegistrationBean<MdcUserIdFilter> mdcUserIdFilterRegistration(
        ObjectProvider<Tracer> tracerProvider) {
      Tracer tracer = tracerProvider.getIfAvailable();
      FilterRegistrationBean<MdcUserIdFilter> registration = new FilterRegistrationBean<>();
      registration.setFilter(new MdcUserIdFilter(tracer));
      registration.addUrlPatterns("/*");
      // Run after Spring Security (order ~100) so SecurityContext is already populated
      registration.setOrder(Ordered.LOWEST_PRECEDENCE - 10);
      registration.setName("mdcUserIdFilter");
      return registration;
    }
  }

  /** Conditionally loads Reactive (WebFlux) security configuration. */
  @Configuration
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
  @ConditionalOnClass(name = "org.springframework.web.reactive.DispatcherHandler")
  @Import(WebSecurityAutoConfiguration.class)
  static class ReactiveSecurityImportConfig {

    /** Seeds userId into SLF4J MDC for every reactive request. */
    @Bean
    @ConditionalOnBean(Tracer.class)
    @ConditionalOnMissingBean
    public MdcUserIdWebFilter mdcUserIdWebFilter(ObjectProvider<Tracer> tracerProvider) {
      return new MdcUserIdWebFilter(tracerProvider.getIfAvailable());
    }
  }

  /** Conditionally loads Gateway-specific security components. */
  @Configuration
  @ConditionalOnClass(
      name = "org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory")
  static class GatewaySecurityConfig {

    @Bean
    @ConditionalOnMissingBean
    public ReactiveJwtDecoder reactiveJwtDecoder(
        @Value("${jwt.secret-key:}") String secretKey,
        @Autowired(required = false) KeyPair keyPair) {
      if (secretKey != null && !secretKey.isBlank()) {
        return NimbusReactiveJwtDecoder.withSecretKey(
                new SecretKeySpec(secretKey.getBytes(), "HmacSHA256"))
            .build();
      }
      if (keyPair != null && keyPair.getPublic() instanceof RSAPublicKey) {
        return NimbusReactiveJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
      }
      throw new IllegalStateException(
          "Neither jwt.secret-key nor RSA KeyPair provided for ReactiveJwtDecoder");
    }

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
