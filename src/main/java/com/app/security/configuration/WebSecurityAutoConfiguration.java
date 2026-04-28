package com.app.security.configuration;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class WebSecurityAutoConfiguration {

  public static @NonNull CorsConfiguration getCorsConfiguration(SecurityProperties.Cors cors) {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(cors.allowedOrigins());
    configuration.setAllowedMethods(cors.allowedMethods());
    configuration.setAllowedHeaders(cors.allowedHeaders());
    configuration.setAllowCredentials(cors.allowCredentials());
    return configuration;
  }
}
