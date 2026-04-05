package com.ecommerce.security.config;

import com.ecommerce.security.filter.UserContextFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Shared Spring Security configuration for microserivces.
 *
 * <p>Renamed from SharedSecurityAutoConfiguration as per user naming preference. This configuration
 * also imports SecurityWebMvcConfig for argument resolution.
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Import(SecurityWebMvcConfig.class)
public class WebSecurityAutoConfiguration {

  @Configuration
  @EnableWebSecurity
  @EnableMethodSecurity
  public static class ServletSecurityConfig {

    @Bean
    public UserContextFilter userContextFilter() {
      return new UserContextFilter();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http, UserContextFilter userContextFilter) throws Exception {
      return http.csrf(AbstractHttpConfigurer::disable)
          .sessionManagement(
              session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .authorizeHttpRequests(
              auth ->
                  auth.requestMatchers(
                          "/api/auth/**",
                          "/login",
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
}
