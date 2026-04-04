package com.ecommerce.security.user;

import org.jspecify.annotations.NonNull;
import org.springframework.core.MethodParameter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Resolver for the @CurrentUser annotation.
 *
 * <p>This class extracts the authenticated user's ID from the SecurityContext and injects it into
 * any controller parameter annotated with @CurrentUser.
 */
public class CurrentUserArgumentResolver implements HandlerMethodArgumentResolver {

  @Override
  public boolean supportsParameter(MethodParameter parameter) {
    return parameter.hasParameterAnnotation(CurrentUser.class)
        && parameter.getParameterType().equals(String.class);
  }

  @Override
  public Object resolveArgument(
          @NonNull MethodParameter parameter,
          ModelAndViewContainer mavContainer,
          @NonNull NativeWebRequest webRequest,
          WebDataBinderFactory binderFactory) {

    var authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || authentication.getName() == null) {
      return null;
    }
    return authentication.getName();
  }
}
