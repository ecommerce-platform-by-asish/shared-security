package com.app.security.configuration;

import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

/**
 * Naming-based resolution for Reactive CORS components to avoid collisions with Servlet-based ones.
 */
public interface ReactiveCorsConfigurationSource extends CorsConfigurationSource {}

/** Concrete implementation of the naming-based Reactive CORS source. */
class NamedReactiveCorsSource extends UrlBasedCorsConfigurationSource
    implements ReactiveCorsConfigurationSource {}
