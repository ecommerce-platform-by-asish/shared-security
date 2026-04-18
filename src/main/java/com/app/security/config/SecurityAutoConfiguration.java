package com.app.security.config;

import com.app.security.exception.RsaException;
import com.app.security.gateway.AuthenticationFilter;
import com.app.security.jwt.JwtProvider;
import com.app.security.jwt.RedisTokenBlacklistManager;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
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

  @Configuration
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  @ConditionalOnClass(name = "jakarta.servlet.DispatcherType")
  @Import(WebSecurityAutoConfiguration.class)
  static class WebSecurityImportConfig {}

  @Configuration
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
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
    public ReactiveJwtDecoder reactiveJwtDecoder(
        @Value("${jwt.secret-key:}") String secretKey,
        @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}") String jwkSetUri,
        @Autowired(required = false) KeyPair keyPair) {
      if (secretKey != null && !secretKey.isBlank()) {
        return NimbusReactiveJwtDecoder.withSecretKey(
                new SecretKeySpec(secretKey.getBytes(), "HmacSHA256"))
            .build();
      }
      if (jwkSetUri != null && !jwkSetUri.isBlank()) {
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
      }
      if (keyPair != null && keyPair.getPublic() instanceof RSAPublicKey) {
        return NimbusReactiveJwtDecoder.withPublicKey((RSAPublicKey) keyPair.getPublic()).build();
      }
      throw new IllegalStateException(
          "Neither jwt.secret-key, spring.security.oauth2.resourceserver.jwt.jwk-set-uri, nor RSA KeyPair provided for ReactiveJwtDecoder");
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

  /** Configuration for generating RSA KeyPairs for development or test environments. */
  @Configuration
  @ConditionalOnProperty(
      name = "shared.security.rsa.generate",
      havingValue = "true",
      matchIfMissing = true)
  static class RsaKeyGenerationConfig {

    @Bean
    @ConditionalOnMissingBean
    public KeyPair rsaKeyPair() {
      try {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
      } catch (NoSuchAlgorithmException e) {
        throw new RsaException("Failed to generate RSA KeyPair", e);
      }
    }
  }
}
