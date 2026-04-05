package com.ecommerce.security.jwt;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import reactor.core.publisher.Mono;

/** Unified manager for token revocation. Supports both blocking and reactive Redis operations. */
public class TokenBlacklistManager {

  private final StringRedisTemplate blockingTemplate;
  private final ReactiveStringRedisTemplate reactiveTemplate;

  public TokenBlacklistManager(
      @Autowired(required = false) StringRedisTemplate blockingTemplate,
      @Autowired(required = false) ReactiveStringRedisTemplate reactiveTemplate) {
    this.blockingTemplate = blockingTemplate;
    this.reactiveTemplate = reactiveTemplate;
  }

  /** Adds a token to the blacklist (blocking). */
  public void blacklist(String jti, Duration timeToLive) {
    if (blockingTemplate != null && jti != null && !jti.isBlank()) {
      blockingTemplate.opsForValue().set("jwt:blacklist:" + jti, "true", timeToLive);
    }
  }

  /** Checks if a token is blacklisted (reactive). */
  public Mono<Boolean> isBlacklisted(String jti) {
    if (jti == null || jti.isBlank()) {
      return Mono.just(false);
    }
    if (reactiveTemplate != null) {
      return reactiveTemplate.hasKey("jwt:blacklist:" + jti).defaultIfEmpty(false);
    }
    if (blockingTemplate != null) {
      return Mono.fromCallable(
              () -> Boolean.TRUE.equals(blockingTemplate.hasKey("jwt:blacklist:" + jti)))
          .defaultIfEmpty(false);
    }
    return Mono.just(false);
  }
}
