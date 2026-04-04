package com.ecommerce.security.config;

import com.ecommerce.security.filter.UserContextFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Shared Spring Security configuration for microservices.
 *
 * <p>This configuration enforces stateless sessions, permits all requests by default (expecting
 * authorization at Method level via @PreAuthorize), and adds the UserContextFilter to populate the
 * SecurityContext from trusted headers.
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
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
          .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
          .addFilterBefore(userContextFilter, UsernamePasswordAuthenticationFilter.class)
          .build();
    }
  }
}
