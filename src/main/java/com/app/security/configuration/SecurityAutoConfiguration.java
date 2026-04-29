package com.app.security.configuration;

import static com.app.security.model.SecurityConstants.ALGORITHM_RSA;

import com.app.security.exception.RsaException;
import com.app.security.filter.GatewayAuthenticationFilter;
import com.app.security.model.SecurityConstants;
import com.app.security.token.JwtProvider;
import com.app.security.token.RedisTokenBlacklistManager;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
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
import org.springframework.data.redis.core.RedisOperations;
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

      return Optional.ofNullable(properties.jwt().jwkSetUri())
          .filter(uri -> !uri.isBlank())
          .map(uri -> NimbusReactiveJwtDecoder.withJwkSetUri(uri).build())
          .or(
              () ->
                  Optional.ofNullable(oauth2Properties)
                      .map(OAuth2ResourceServerProperties::getJwt)
                      .map(OAuth2ResourceServerProperties.Jwt::getJwkSetUri)
                      .filter(uri -> !uri.isBlank())
                      .map(uri -> NimbusReactiveJwtDecoder.withJwkSetUri(uri).build()))
          .or(
              () ->
                  Optional.ofNullable(properties.jwt().secretKey())
                      .filter(key -> !key.isBlank())
                      .map(
                          key ->
                              NimbusReactiveJwtDecoder.withSecretKey(
                                      new SecretKeySpec(
                                          key.getBytes(), SecurityConstants.ALGORITHM_HMAC_256))
                                  .build()))
          .or(
              () ->
                  Optional.ofNullable(keyPair)
                      .map(KeyPair::getPublic)
                      .filter(RSAPublicKey.class::isInstance)
                      .map(RSAPublicKey.class::cast)
                      .map(key -> NimbusReactiveJwtDecoder.withPublicKey(key).build()))
          .orElseThrow(
              () ->
                  new IllegalStateException(
                      "No valid JWT decoding configuration provided (JWK URI, Secret, or RSA Key)"));
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
  @ConditionalOnClass(RedisOperations.class)
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
      matchIfMissing = false)
  static class RsaKeyGenerationConfig {

    @Bean
    @ConditionalOnMissingBean
    public KeyPair rsaKeyPair() {
      log.warn(
          "!!! CAUTION !!! - Auto-generating a transient RSA KeyPair. "
              + "This is ONLY intended for development/test. "
              + "In production, provide a persistent KeyPair bean or configuration.");
      try {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
        generator.initialize(2048);
        return generator.generateKeyPair();
      } catch (NoSuchAlgorithmException e) {
        throw new RsaException("Failed to generate RSA KeyPair", e);
      }
    }
  }
}
