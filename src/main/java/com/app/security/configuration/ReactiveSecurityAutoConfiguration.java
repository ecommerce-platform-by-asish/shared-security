package com.app.security.configuration;

import com.app.security.filter.PublicPathResolver;
import com.app.security.filter.UserContextWebFilter;
import io.micrometer.tracing.Tracer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@org.springframework.boot.autoconfigure.condition.ConditionalOnClass(
    org.springframework.security.web.server.SecurityWebFilterChain.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@EnableWebFluxSecurity
public class ReactiveSecurityAutoConfiguration {

  @Bean
  public PublicPathResolver publicPathResolver(ApplicationContext context) {
    return PublicPathResolver.reactive(context);
  }

  @Bean
  public org.springframework.web.cors.reactive.CorsConfigurationSource corsConfigurationSource(
      SecurityProperties properties) {
    CorsConfiguration configuration =
        WebSecurityAutoConfiguration.getCorsConfiguration(properties.cors());
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
