package com.app.security.filter;

import com.app.security.annotation.PublicEndpoint;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.web.method.HandlerMethod;

/**
 * Strategy interface for resolving the complete set of publicly accessible security paths. Unifies
 * static defaults, external configuration, and dynamic @PublicEndpoint discovery.
 */
@FunctionalInterface
public interface PublicPathResolver {

  Set<String> DEFAULT_PATHS =
      Set.of(
          "/api/auth/**",
          "/login",
          "/logout",
          "/.well-known/**",
          "/v3/api-docs/**",
          "/swagger-ui/**",
          "/swagger-ui.html",
          "/webjars/**",
          "/actuator/health");

  /**
   * Resolves the final set of permitted paths.
   *
   * @param customPaths Optional additional paths from configuration.
   * @return A unique array of path patterns.
   */
  String[] resolve(List<String> customPaths);

  /** Factory method for Servlet-based (MVC) applications. */
  static PublicPathResolver mvc(ApplicationContext context) {
    return new CachedResolver(
        "Servlet",
        () -> {
          var mapping =
              context.getBean(
                  "requestMappingHandlerMapping",
                  org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping
                      .class);
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
                          .map(org.springframework.web.util.pattern.PathPattern::getPatternString))
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
    return method.hasMethodAnnotation(PublicEndpoint.class)
        || method.getBeanType().isAnnotationPresent(PublicEndpoint.class);
  }

  private static String normalize(String path) {
    if (path == null || path.isBlank() || path.equals("/")) return "/";
    return path.startsWith("/") ? path : "/" + path;
  }
}
