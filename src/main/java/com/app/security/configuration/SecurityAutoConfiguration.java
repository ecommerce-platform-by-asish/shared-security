package com.app.security.configuration;

import com.app.security.exception.RsaException;
import com.app.security.filter.GatewayAuthenticationFilter;
import com.app.security.model.SecurityConstants;
import com.app.security.token.JwtProvider;
import com.app.security.token.RedisTokenBlacklistManager;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
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
@Slf4j
@Configuration
@Import(WebSecurityAutoConfiguration.class)
public class SecurityAutoConfiguration {

  /** Creates the component for token generation and verification. */
  @Bean
  @ConditionalOnMissingBean
  public JwtProvider jwtProvider(
      SecurityProperties properties, @Autowired(required = false) KeyPair keyPair) {
    return new JwtProvider(properties, keyPair);
  }

  /** Sets BCrypt as the standard password hashing algorithm. */
  @Bean
  @ConditionalOnMissingBean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  /** Conditionally loads Gateway-specific security components. */
  @Configuration
  @ConditionalOnClass(
      name = "org.springframework.cloud.gateway.filter.factory.GatewayFilterFactory")
  static class GatewaySecurityConfig {

    @Bean
    @ConditionalOnMissingBean
    public ReactiveJwtDecoder reactiveJwtDecoder(
        SecurityProperties properties,
        @Autowired(required = false) OAuth2ResourceServerProperties oauth2Properties,
        @Autowired(required = false) KeyPair keyPair) {
      String secretKey = properties.jwt().secretKey();
      String jwkSetUri = properties.jwt().jwkSetUri();

      // Priority 1: Custom Property
      if (jwkSetUri != null && !jwkSetUri.isBlank()) {
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
      }

      // Priority 2: Standard Spring Property
      if (oauth2Properties != null && oauth2Properties.getJwt() != null) {
        String springJwkSetUri = oauth2Properties.getJwt().getJwkSetUri();
        if (springJwkSetUri != null && !springJwkSetUri.isBlank()) {
          return NimbusReactiveJwtDecoder.withJwkSetUri(springJwkSetUri).build();
        }
      }

      if (secretKey != null && !secretKey.isBlank()) {
        return NimbusReactiveJwtDecoder.withSecretKey(
                new SecretKeySpec(secretKey.getBytes(), SecurityConstants.ALGORITHM_HMAC_256))
            .build();
      }

      if (keyPair != null && keyPair.getPublic() instanceof RSAPublicKey rsaPublicKey) {
        return NimbusReactiveJwtDecoder.withPublicKey(rsaPublicKey).build();
      }
      throw new IllegalStateException(
          "Neither jwk-set-uri, secret-key, nor RSA KeyPair provided for ReactiveJwtDecoder");
    }

    @Bean
    @ConditionalOnMissingBean
    public GatewayAuthenticationFilter authenticationFilter(
        ReactiveJwtDecoder jwtDecoder,
        @Autowired(required = false) RedisTokenBlacklistManager blacklistManager) {
      return new GatewayAuthenticationFilter(jwtDecoder, blacklistManager);
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
      name = "app.security.rsa.generate",
      havingValue = "true",
      matchIfMissing = true)
  static class RsaKeyGenerationConfig {

    @Bean
    @ConditionalOnMissingBean
    public KeyPair rsaKeyPair() {
      log.warn(
          "!!! CAUTION !!! - Auto-generating a transient RSA KeyPair. "
              + "This is ONLY intended for development/test. "
              + "In production, provide a persistent KeyPair bean or configuration.");
      try {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(SecurityConstants.ALGORITHM_RSA);
        generator.initialize(2048);
        return generator.generateKeyPair();
      } catch (NoSuchAlgorithmException e) {
        throw new RsaException("Failed to generate RSA KeyPair", e);
      }
    }
  }
}
