package com.ecommerce.security.jwt;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import reactor.core.publisher.Mono;

/**
 * Handles token revocation using Redis. 
 * Supports both blocking and reactive operations in a single manager.
 */
public class RedisTokenBlacklistManager {

  private final StringRedisTemplate redisTemplate;
  private final ReactiveStringRedisTemplate reactiveRedisTemplate;

  public RedisTokenBlacklistManager(
      @Autowired(required = false) StringRedisTemplate redisTemplate,
      @Autowired(required = false) ReactiveStringRedisTemplate reactiveRedisTemplate) {
    this.redisTemplate = redisTemplate;
    this.reactiveRedisTemplate = reactiveRedisTemplate;
  }

  /** Adds a token ID to the Redis blacklist. */
  public void blacklist(String jti, Duration timeToLive) {
    if (redisTemplate != null && jti != null && !jti.isBlank()) {
      redisTemplate.opsForValue().set("jwt:blacklist:" + jti, "true", timeToLive);
    }
  }

  /** Checks if a token ID is in the Redis blacklist. */
  public Mono<Boolean> isBlacklisted(String jti) {
    if (jti == null || jti.isBlank()) {
      return Mono.just(false);
    }
    if (reactiveRedisTemplate != null) {
      return reactiveRedisTemplate.hasKey("jwt:blacklist:" + jti).defaultIfEmpty(false);
    }
    if (redisTemplate != null) {
      return Mono.fromCallable(() -> Boolean.TRUE.equals(redisTemplate.hasKey("jwt:blacklist:" + jti)))
          .defaultIfEmpty(false);
    }
    return Mono.just(false);
  }
}
