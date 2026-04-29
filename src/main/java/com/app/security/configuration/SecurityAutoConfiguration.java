package com.app.security.configuration;

import static com.app.security.model.SecurityConstants.ALGORITHM_HMAC_256;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import com.app.security.exception.handler.SecurityExceptionHandler;
import com.app.security.filter.GatewayAuthenticationGatewayFilterFactory;
import com.app.security.filter.PublicPathResolver;
import com.app.security.filter.UserContextFilter;
import com.app.security.token.JwtProvider;
import com.app.security.token.RedisTokenBlacklistManager;
import io.micrometer.observation.ObservationRegistry;
import io.micrometer.tracing.Tracer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
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
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/** Auto-configures common security including JWT decoders, filters, and password encoders. */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityAutoConfiguration {

  @Bean
  @ConditionalOnProperty(name = "app.security.rsa.generate", havingValue = "true")
  @ConditionalOnMissingBean
  public KeyPair keyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    return generator.generateKeyPair();
  }

  public static @NonNull CorsConfiguration getCorsConfiguration(SecurityProperties.Cors cors) {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(cors.allowedOrigins());
    configuration.setAllowedMethods(cors.allowedMethods());
    configuration.setAllowedHeaders(cors.allowedHeaders());
    configuration.setAllowCredentials(cors.allowCredentials());
    return configuration;
  }

  @Bean
  @ConditionalOnClass(name = "org.springframework.security.crypto.password.PasswordEncoder")
  @ConditionalOnMissingBean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtProvider jwtProvider(
      SecurityProperties properties, ObjectProvider<KeyPair> keyPairProvider) {
    return new JwtProvider(properties, keyPairProvider.getIfAvailable());
  }

  @Bean
  @ConditionalOnClass(name = "org.springframework.data.redis.core.RedisTemplate")
  @ConditionalOnMissingBean
  public RedisTokenBlacklistManager redisTokenBlacklistManager(
      ObjectProvider<StringRedisTemplate> blockingTemplateProvider,
      ObjectProvider<ReactiveStringRedisTemplate> reactiveTemplateProvider) {
    return new RedisTokenBlacklistManager(
        blockingTemplateProvider.getIfAvailable(), reactiveTemplateProvider.getIfAvailable());
  }

  @Configuration
  @ConditionalOnClass(SecurityWebFilterChain.class)
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
  @EnableWebFluxSecurity
  @Import(SecurityExceptionHandler.Reactive.class)
  static class ReactiveSecurityConfiguration {

    @Bean
    public PublicPathResolver publicPathResolver(ApplicationContext context) {
      return PublicPathResolver.reactive(context);
    }

    @Bean
    public org.springframework.web.cors.reactive.CorsConfigurationSource corsConfigurationSource(
        SecurityProperties properties) {
      CorsConfiguration configuration = getCorsConfiguration(properties.cors());
      var source = new org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", configuration);
      return source;
    }

    @Bean
    @ConditionalOnMissingClass("org.springframework.cloud.gateway.filter.GlobalFilter")
    public UserContextFilter.Reactive userContextWebFilter(ObjectProvider<Tracer> tracerProvider) {
      return new UserContextFilter.Reactive(tracerProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public ReactiveJwtDecoder reactiveJwtDecoder(SecurityProperties properties) {
      String jwkSetUri = properties.jwt().jwkSetUri();
      return NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
    }

    @Bean
    public GatewayAuthenticationGatewayFilterFactory gatewayAuthenticationFilter(
        ReactiveJwtDecoder jwtDecoder,
        ObjectProvider<RedisTokenBlacklistManager> blacklistManagerProvider,
        ObjectProvider<Tracer> tracerProvider,
        ObjectProvider<ObservationRegistry> observationRegistryProvider) {
      return new GatewayAuthenticationGatewayFilterFactory(
          jwtDecoder,
          blacklistManagerProvider.getIfAvailable(),
          tracerProvider,
          observationRegistryProvider);
    }

    @Bean
    @ConditionalOnMissingBean(SecurityWebFilterChain.class)
    public SecurityWebFilterChain springSecurityFilterChain(
        ServerHttpSecurity http,
        PublicPathResolver resolver,
        SecurityProperties properties,
        ObjectProvider<UserContextFilter.Reactive> userContextWebFilterProvider) {
      http.cors(Customizer.withDefaults())
          .csrf(ServerHttpSecurity.CsrfSpec::disable)
          .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
          .authorizeExchange(
              exchanges ->
                  exchanges
                      .pathMatchers(OPTIONS, "/**")
                      .permitAll()
                      .pathMatchers(resolver.resolve(properties.publicPaths()))
                      .permitAll()
                      .anyExchange()
                      .authenticated());

      userContextWebFilterProvider.ifAvailable(
          filter -> http.addFilterAt(filter, SecurityWebFiltersOrder.AUTHENTICATION));

      return http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())).build();
    }
  }

  @Configuration
  @ConditionalOnClass(SecurityFilterChain.class)
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  @EnableWebSecurity
  @EnableMethodSecurity
  @Import(SecurityExceptionHandler.Servlet.class)
  static class ServletSecurityConfiguration {

    @Bean
    public PublicPathResolver publicPathResolver(ApplicationContext context) {
      return PublicPathResolver.mvc(context);
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource(SecurityProperties properties) {
      CorsConfiguration configuration = getCorsConfiguration(properties.cors());
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", configuration);
      return source;
    }

    @Bean
    public UserContextFilter.Servlet userContextFilter(ObjectProvider<Tracer> tracerProvider) {
      return new UserContextFilter.Servlet(tracerProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtDecoder jwtDecoder(
        SecurityProperties properties, ObjectProvider<KeyPair> keyPairProvider) {
      String secretKey = properties.jwt().secretKey();
      KeyPair keyPair = keyPairProvider.getIfAvailable();
      if (keyPair != null && keyPair.getPublic() instanceof RSAPublicKey rsaPublicKey) {
        return NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
      }
      if (secretKey != null && !secretKey.isBlank()) {
        return NimbusJwtDecoder.withSecretKey(
                new SecretKeySpec(secretKey.getBytes(), ALGORITHM_HMAC_256))
            .build();
      }
      String jwkSetUri = properties.jwt().jwkSetUri();
      if (jwkSetUri != null && !jwkSetUri.isBlank()) {
        return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
      }
      return null;
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        UserContextFilter.Servlet userContextFilter,
        PublicPathResolver resolver,
        SecurityProperties properties,
        ObjectProvider<JwtDecoder> jwtDecoderProvider)
        throws Exception {
      http.cors(Customizer.withDefaults())
          .csrf(AbstractHttpConfigurer::disable)
          .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
          .logout(LogoutConfigurer::disable)
          .authorizeHttpRequests(
              auth ->
                  auth.requestMatchers(OPTIONS, "/**")
                      .permitAll()
                      .requestMatchers(resolver.resolve(properties.publicPaths()))
                      .permitAll()
                      .anyRequest()
                      .authenticated());

      if (jwtDecoderProvider.getIfAvailable() != null) {
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
      }

      return http.addFilterBefore(userContextFilter, UsernamePasswordAuthenticationFilter.class)
          .build();
    }
  }
}
