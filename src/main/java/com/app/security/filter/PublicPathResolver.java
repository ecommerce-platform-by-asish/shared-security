package com.app.security.filter;

import com.app.security.annotation.SecurityRules;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPattern;

/** Strategy for resolving publicly accessible API paths for all services. */
@FunctionalInterface
public interface PublicPathResolver {

  Set<String> DEFAULT_PATHS =
      Set.of(
          "/login",
          "/**/login",
          "/logout",
          "/**/logout",
          "/register",
          "/**/register",
          "/.well-known/**",
          "/api/*/.well-known/**",
          "/v3/api-docs/**",
          "/api/*/v3/api-docs/**",
          "/swagger-ui/**",
          "/api/*/swagger-ui/**",
          "/swagger-ui.html",
          "/**/swagger-ui.html",
          "/webjars/**",
          "/api/*/webjars/**",
          "/actuator/**");

  /** Resolves the merged set of default, configured, and discovery-based public paths. */
  String[] resolve(List<String> customPaths);

  /** Factory method for Servlet-based (MVC) applications. */
  static PublicPathResolver mvc(ApplicationContext context) {
    return new CachedResolver(
        "Servlet",
        () -> {
          var mapping =
              context.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
          return mapping.getHandlerMethods().entrySet().stream()
              .filter(e -> isPublic(e.getValue()))
              .filter(e -> e.getKey().getPathPatternsCondition() != null)
              .flatMap(e -> e.getKey().getPathPatternsCondition().getPatternValues().stream())
              .toList();
        });
  }

  /** Factory method for Reactive (WebFlux) applications. */
  static PublicPathResolver reactive(ApplicationContext context) {
    return new CachedResolver(
        "Reactive",
        () -> {
          var mapping =
              context.getBean(
                  "requestMappingHandlerMapping",
                  org.springframework.web.reactive.result.method.annotation
                      .RequestMappingHandlerMapping.class);
          return mapping.getHandlerMethods().entrySet().stream()
              .filter(e -> isPublic(e.getValue()))
              .flatMap(
                  e ->
                      e.getKey().getPatternsCondition().getPatterns().stream()
                          .map(PathPattern::getPatternString))
              .toList();
        });
  }

  /** Internal implementation that caches discovered paths to avoid redundant scans. */
  @Slf4j
  final class CachedResolver implements PublicPathResolver {
    private final String environment;
    private final Supplier<List<String>> discoverySource;
    private volatile List<String> discoveredPaths;

    CachedResolver(String environment, Supplier<List<String>> discoverySource) {
      this.environment = environment;
      this.discoverySource = discoverySource;
    }

    @Override
    public String[] resolve(List<String> customPaths) {
      if (discoveredPaths == null) {
        synchronized (this) {
          if (discoveredPaths == null) {
            discoveredPaths = discover();
          }
        }
      }

      Set<String> merged = new LinkedHashSet<>(DEFAULT_PATHS);
      if (customPaths != null) {
        customPaths.forEach(p -> merged.add(normalize(p)));
      }
      discoveredPaths.forEach(p -> merged.add(normalize(p)));

      String[] result = merged.toArray(String[]::new);
      log.info(
          "Resolved {} public paths for {} environment: {}",
          result.length,
          environment,
          Arrays.toString(result));
      return result;
    }

    private List<String> discover() {
      try {
        return discoverySource.get();
      } catch (Exception e) {
        log.debug("Mapping discovery skipped for {}: {}", environment, e.getMessage());
        return List.of();
      }
    }
  }

  private static boolean isPublic(HandlerMethod method) {
    return method.hasMethodAnnotation(SecurityRules.PublicEndpoint.class)
        || method.getBeanType().isAnnotationPresent(SecurityRules.PublicEndpoint.class);
  }

  private static String normalize(String path) {
    return Optional.ofNullable(path)
        .filter(p -> !p.isBlank() && !p.equals("/"))
        .map(p -> p.startsWith("/") ? p : "/" + p)
        .orElse("/");
  }
}
