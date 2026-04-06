package com.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Filter that adds the authenticated userId to SLF4J MDC for consistent log lines. */
public class MdcUserIdFilter extends OncePerRequestFilter {

  public static final String MDC_USER_ID_KEY = "userId";

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null && auth.isAuthenticated() && auth.getPrincipal() instanceof String userId) {
      MDC.put(MDC_USER_ID_KEY, userId);
    }
    try {
      filterChain.doFilter(request, response);
    } finally {
      MDC.remove(MDC_USER_ID_KEY);
    }
  }
}
