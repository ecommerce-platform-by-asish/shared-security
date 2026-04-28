package com.app.security.configuration;

import com.app.security.filter.PublicPathResolver;
import com.app.security.filter.UserContextFilter;
import com.app.security.model.SecurityConstants;
import io.micrometer.tracing.Tracer;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
@EnableMethodSecurity
public class ServletSecurityAutoConfiguration {

  @Bean
  public PublicPathResolver publicPathResolver(ApplicationContext context) {
    return PublicPathResolver.mvc(context);
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource(SecurityProperties properties) {
    CorsConfiguration configuration =
        WebSecurityAutoConfiguration.getCorsConfiguration(properties.cors());
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  @Bean
  public UserContextFilter userContextFilter(ObjectProvider<Tracer> tracerProvider) {
    return new UserContextFilter(tracerProvider.getIfAvailable());
  }

  @Bean
  @ConditionalOnMissingBean
  public JwtDecoder jwtDecoder(
      SecurityProperties properties, @Autowired(required = false) KeyPair keyPair) {
    String secretKey = properties.jwt().secretKey();
    if (keyPair != null && keyPair.getPublic() instanceof RSAPublicKey rsaPublicKey) {
      return NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
    }
    if (secretKey != null && !secretKey.isBlank()) {
      return NimbusJwtDecoder.withSecretKey(
              new SecretKeySpec(secretKey.getBytes(), SecurityConstants.ALGORITHM_HMAC_256))
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
      UserContextFilter userContextFilter,
      PublicPathResolver resolver,
      SecurityProperties properties,
      ObjectProvider<JwtDecoder> jwtDecoderProvider)
      throws Exception {
    http.cors(Customizer.withDefaults())
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .logout(LogoutConfigurer::disable)
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers(HttpMethod.OPTIONS, "/**")
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
