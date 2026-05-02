package com.app.security.configuration;

import static com.app.security.model.SecurityConstants.ALGORITHM_HMAC_256;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import com.app.security.exception.handler.SecurityExceptionHandler;
import com.app.security.filter.PublicPathResolver;
import com.app.security.filter.UserContextFilter;
import com.app.security.token.JwtProvider;
import com.app.security.token.RedisTokenBlacklistManager;
import com.app.security.util.SecurityUtils;
import io.micrometer.tracing.Tracer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.config.WebFluxConfigurer;

/**
 * Main Security Auto-Configuration. Acts as the entry point for shared security infrastructure.
 * Consolidates stack-specific logic into inner classes using standard imports.
 */
@Slf4j
@AutoConfiguration
@EnableConfigurationProperties(SecurityProperties.class)
@Import(JpaAuditingConfiguration.class)
public class SecurityAutoConfiguration {

  @Bean
  @ConditionalOnProperty(name = "app.security.rsa.generate", havingValue = "true")
  @ConditionalOnMissingBean
  public KeyPair keyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  @Bean
  @ConditionalOnMissingBean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtProvider jwtProvider(SecurityProperties properties, ObjectProvider<KeyPair> keyPair) {
    return new JwtProvider(properties, keyPair.getIfAvailable());
  }

  @Bean
  @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
  @ConditionalOnMissingBean
  public RedisTokenBlacklistManager redisTokenBlacklistManager(
      ObjectProvider<StringRedisTemplate> blocking,
      ObjectProvider<ReactiveStringRedisTemplate> reactive) {
    return new RedisTokenBlacklistManager(blocking.getIfAvailable(), reactive.getIfAvailable());
  }

  /** REACTIVE STACK CONFIGURATION */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass({WebFluxConfigurer.class, EnableWebFluxSecurity.class})
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
  @EnableWebFluxSecurity
  @Import(SecurityExceptionHandler.Reactive.class)
  static class ReactiveSecurityConfiguration {

    @Bean
    public ReactiveCorsConfigurationSource corsConfigurationSource(SecurityProperties props) {
      var source = new NamedReactiveCorsSource();
      source.registerCorsConfiguration("/**", SecurityUtils.buildCors(props.cors()));
      return source;
    }

    @Bean
    @ConditionalOnMissingBean
    public ReactiveJwtDecoder reactiveJwtDecoder(
        SecurityProperties props, ObjectProvider<KeyPair> kp) {
      var jwtProps = props.jwt();
      return Optional.ofNullable(kp.getIfAvailable())
          .map(KeyPair::getPublic)
          .filter(RSAPublicKey.class::isInstance)
          .map(p -> (RSAPublicKey) p)
          .map(pub -> NimbusReactiveJwtDecoder.withPublicKey(pub).build())
          .or(
              () ->
                  Optional.ofNullable(jwtProps.secretKey())
                      .filter(s -> !s.isBlank())
                      .map(
                          s ->
                              NimbusReactiveJwtDecoder.withSecretKey(
                                      new SecretKeySpec(s.getBytes(), ALGORITHM_HMAC_256))
                                  .build()))
          .or(
              () ->
                  Optional.ofNullable(jwtProps.jwkSetUri())
                      .filter(u -> !u.isBlank())
                      .map(u -> NimbusReactiveJwtDecoder.withJwkSetUri(u).build()))
          .orElseThrow(
              () ->
                  new IllegalStateException(
                      "No ReactiveJwtDecoder could be configured. Check app.security.jwt properties."));
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
        ServerHttpSecurity http,
        ApplicationContext context,
        SecurityProperties props,
        ObjectProvider<Tracer> tracer,
        ReactiveJwtDecoder decoder) {

      String[] publics = PublicPathResolver.reactive(context).resolve(props.publicPaths());

      http.cors(Customizer.withDefaults())
          .csrf(ServerHttpSecurity.CsrfSpec::disable)
          .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
          .authorizeExchange(
              ex ->
                  ex.pathMatchers(OPTIONS, "/**")
                      .permitAll()
                      .pathMatchers(publics)
                      .permitAll()
                      .anyExchange()
                      .authenticated())
          .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtDecoder(decoder)));

      http.addFilterAt(
          new UserContextFilter.Reactive(tracer.getIfAvailable()),
          SecurityWebFiltersOrder.AUTHENTICATION);

      return http.build();
    }
  }

  /** SERVLET STACK CONFIGURATION */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass({jakarta.servlet.Filter.class, EnableWebSecurity.class})
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  @EnableWebSecurity
  @EnableMethodSecurity
  @Import(SecurityExceptionHandler.Servlet.class)
  static class ServletSecurityConfiguration {

    @Bean
    public CorsConfigurationSource corsConfigurationSource(SecurityProperties props) {
      var source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", SecurityUtils.buildCors(props.cors()));
      return source;
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(SecurityProperties props, ObjectProvider<KeyPair> kp) {
      var jwtProps = props.jwt();
      return Optional.ofNullable(kp.getIfAvailable())
          .map(KeyPair::getPublic)
          .filter(RSAPublicKey.class::isInstance)
          .map(p -> (RSAPublicKey) p)
          .map(pub -> NimbusJwtDecoder.withPublicKey(pub).build())
          .or(
              () ->
                  Optional.ofNullable(jwtProps.secretKey())
                      .filter(s -> !s.isBlank())
                      .map(
                          s ->
                              NimbusJwtDecoder.withSecretKey(
                                      new SecretKeySpec(s.getBytes(), ALGORITHM_HMAC_256))
                                  .build()))
          .or(
              () ->
                  Optional.ofNullable(jwtProps.jwkSetUri())
                      .filter(u -> !u.isBlank())
                      .map(u -> NimbusJwtDecoder.withJwkSetUri(u).build()))
          .orElse(null);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        ApplicationContext context,
        SecurityProperties props,
        ObjectProvider<Tracer> tracer,
        ObjectProvider<JwtDecoder> decoderProvider)
        throws Exception {

      String[] publics = PublicPathResolver.mvc(context).resolve(props.publicPaths());
      JwtDecoder decoder = decoderProvider.getIfAvailable();

      http.cors(Customizer.withDefaults())
          .csrf(AbstractHttpConfigurer::disable)
          .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
          .authorizeHttpRequests(
              auth ->
                  auth.requestMatchers(OPTIONS, "/**")
                      .permitAll()
                      .requestMatchers(publics)
                      .permitAll()
                      .anyRequest()
                      .authenticated());

      if (decoder != null) {
        http.oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.decoder(decoder)));
      }

      http.addFilterAfter(
          new UserContextFilter.Servlet(tracer.getIfAvailable()),
          BearerTokenAuthenticationFilter.class);

      return http.build();
    }
  }
}
