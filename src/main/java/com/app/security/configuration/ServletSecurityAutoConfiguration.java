package com.app.security.configuration;

import com.app.security.filter.PublicPathResolver;
import com.app.security.filter.UserContextFilter;
import io.micrometer.tracing.Tracer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@org.springframework.boot.autoconfigure.condition.ConditionalOnClass(
    org.springframework.security.web.SecurityFilterChain.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
@EnableMethodSecurity
public class ServletSecurityAutoConfiguration {

  @Bean
  public PublicPathResolver publicPathResolver(ApplicationContext context) {
    return PublicPathResolver.mvc(context);
  }

  @Bean
  public org.springframework.web.cors.CorsConfigurationSource corsConfigurationSource(
      SecurityProperties properties) {
    CorsConfiguration configuration =
        WebSecurityAutoConfiguration.getCorsConfiguration(properties.cors());
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
      SecurityProperties properties)
      throws Exception {
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
