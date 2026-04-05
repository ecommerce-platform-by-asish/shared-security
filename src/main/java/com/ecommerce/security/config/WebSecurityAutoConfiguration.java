package com.ecommerce.security.config;

import com.ecommerce.security.filter.UserContextFilter;
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

/**
 * Shared security setup for all services. Automatically configures either Servlet or Reactive
 * security based on the application type.
 */
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
    public UserContextFilter userContextFilter() {
      return new UserContextFilter();
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
