package com.app.security.config;

import com.app.security.filter.UserContextFilter;
import io.micrometer.tracing.Tracer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

/** Shared web security rules for all microservices, supporting both Servlet and Reactive apps. */
@Configuration
public class WebSecurityAutoConfiguration {

  /** Security setup for standard (Servlet) web applications. */
  @Configuration
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  @Import(SecurityWebMvcConfig.class)
  @EnableWebSecurity
  @EnableMethodSecurity
  public static class ServletSecurityConfig {

    /** Creates a filter that populates user identity from request headers. */
    @Bean
    public UserContextFilter userContextFilter(ObjectProvider<Tracer> tracerProvider) {
      return new UserContextFilter(tracerProvider.getIfAvailable());
    }

    /** Defines security rules and disables defaults like CSRF and Logout. */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http, UserContextFilter userContextFilter) throws Exception {
      return http.csrf(AbstractHttpConfigurer::disable)
          .sessionManagement(
              session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .logout(LogoutConfigurer::disable)
          .authorizeHttpRequests(
              auth ->
                  auth.requestMatchers(
                          "/api/auth/**",
                          "/login",
                          "/logout",
                          "/.well-known/**",
                          "/v3/api-docs/**",
                          "/swagger-ui/**",
                          "/actuator/health")
                      .permitAll()
                      .anyRequest()
                      .authenticated())
          .addFilterBefore(userContextFilter, UsernamePasswordAuthenticationFilter.class)
          .build();
    }
  }

  /** Security setup for Reactive (WebFlux) apps like the API Gateway. */
  @Configuration
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
  @EnableWebFluxSecurity
  public static class ReactiveSecurityConfig {

    /** Defines security rules for reactive applications. */
    @Bean
    @ConditionalOnMissingBean(SecurityWebFilterChain.class)
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
      return http.csrf(CsrfSpec::disable)
          .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
          .authorizeExchange(
              exchanges ->
                  exchanges
                      .pathMatchers(
                          "/api/auth/**",
                          "/login",
                          "/.well-known/**",
                          "/v3/api-docs/**",
                          "/swagger-ui/**",
                          "/actuator/health")
                      .permitAll()
                      .anyExchange()
                      .authenticated())
          .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
          .build();
    }
  }
}
