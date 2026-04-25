package com.app.security.configuration;

import com.app.security.filter.PublicPathResolver;
import com.app.security.filter.UserContextFilter;
import com.app.security.filter.UserContextWebFilter;
import io.micrometer.tracing.Tracer;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;

/** Shared web security rules for all microservices, supporting both Servlet and Reactive apps. */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class WebSecurityAutoConfiguration {

  /** Security setup for standard (Servlet) web applications. */
  @Configuration
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  @EnableWebSecurity
  @EnableMethodSecurity
  static class ServletSecurityConfig {

    @Bean
    public PublicPathResolver publicPathResolver(ApplicationContext context) {
      return PublicPathResolver.mvc(context);
    }

    /** Configures CORS for Servlet-based applications. */
    @Bean
    public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource(
        SecurityProperties properties) {
      CorsConfiguration configuration = getCorsConfiguration(properties.cors());
      org.springframework.web.cors.UrlBasedCorsConfigurationSource source =
          new org.springframework.web.cors.UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", configuration);
      return source;
    }

    @Bean
    public UserContextFilter userContextFilter(ObjectProvider<Tracer> tracerProvider) {
      return new UserContextFilter(tracerProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        UserContextFilter userContextFilter,
        PublicPathResolver resolver,
        SecurityProperties properties) {
      return http.cors(Customizer.withDefaults())
          .csrf(AbstractHttpConfigurer::disable)
          .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .logout(LogoutConfigurer::disable)
          .authorizeHttpRequests(
              auth ->
                  auth.requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**")
                      .permitAll()
                      .requestMatchers(resolver.resolve(properties.publicPaths()))
                      .permitAll()
                      .anyRequest()
                      .authenticated())
          .addFilterBefore(userContextFilter, UsernamePasswordAuthenticationFilter.class)
          .build();
    }
  }

  /** Creates a standard CORS configuration from the provided properties. */
  private static @NonNull CorsConfiguration getCorsConfiguration(SecurityProperties.Cors cors) {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(cors.allowedOrigins());
    configuration.setAllowedMethods(cors.allowedMethods());
    configuration.setAllowedHeaders(cors.allowedHeaders());
    configuration.setAllowCredentials(cors.allowCredentials());
    return configuration;
  }

  /** Security setup for Reactive (WebFlux) apps like the API Gateway. */
  @Configuration
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
  @EnableWebFluxSecurity
  static class ReactiveSecurityConfig {

    @Bean
    public PublicPathResolver publicPathResolver(ApplicationContext context) {
      return PublicPathResolver.reactive(context);
    }

    /** Configures CORS for Reactive applications. */
    @Bean
    public org.springframework.web.cors.reactive.CorsConfigurationSource corsConfigurationSource(
        SecurityProperties properties) {
      CorsConfiguration configuration = getCorsConfiguration(properties.cors());
      org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource source =
          new org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource();
      source.registerCorsConfiguration("/**", configuration);
      return source;
    }

    @Bean
    public UserContextWebFilter userContextWebFilter(ObjectProvider<Tracer> tracerProvider) {
      return new UserContextWebFilter(tracerProvider.getIfAvailable());
    }

    @Bean
    @ConditionalOnMissingBean(SecurityWebFilterChain.class)
    public SecurityWebFilterChain springSecurityFilterChain(
        ServerHttpSecurity http,
        PublicPathResolver resolver,
        SecurityProperties properties,
        UserContextWebFilter userContextWebFilter) {
      return http.cors(Customizer.withDefaults())
          .csrf(CsrfSpec::disable)
          .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
          .authorizeExchange(
              exchanges ->
                  exchanges
                      .pathMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**")
                      .permitAll()
                      .pathMatchers(resolver.resolve(properties.publicPaths()))
                      .permitAll()
                      .anyExchange()
                      .authenticated())
          .addFilterAt(userContextWebFilter, SecurityWebFiltersOrder.AUTHENTICATION)
          .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
          .build();
    }
  }
}
