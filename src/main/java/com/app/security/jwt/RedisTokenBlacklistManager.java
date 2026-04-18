package com.app.security.jwt;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import reactor.core.publisher.Mono;

/** Manages token blacklisting in Redis to support logout and token revocation. */
@RequiredArgsConstructor(onConstructor_ = @Autowired(required = false))
public class RedisTokenBlacklistManager {

  private final StringRedisTemplate redisTemplate;
  private final ReactiveStringRedisTemplate reactiveRedisTemplate;

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
      return Mono.fromCallable(
              () -> Boolean.TRUE.equals(redisTemplate.hasKey("jwt:blacklist:" + jti)))
          .defaultIfEmpty(false);
    }
    return Mono.just(false);
  }
}
