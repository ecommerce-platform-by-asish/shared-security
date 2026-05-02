package com.app.security.token;

import static com.app.security.model.SecurityConstants.JWT_BLACKLIST;

import java.time.Duration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import reactor.core.publisher.Mono;

/** Manages invalid or logged-out JWT tokens using Redis as a shared store. */
@Slf4j
@RequiredArgsConstructor
public class RedisTokenBlacklistManager {

  private final @Nullable StringRedisTemplate blockingTemplate;
  private final @Nullable ReactiveStringRedisTemplate reactiveTemplate;

  private static String key(String jti) {
    return JWT_BLACKLIST + jti;
  }

  /** Persists a token ID in the blacklist for the specified duration. */
  public void blacklist(String jti, Duration duration) {
    if (blockingTemplate != null) {
      blockingTemplate.opsForValue().set(key(jti), "1", duration);
    } else {
      log.warn("Blocking RedisTemplate not available. Cannot blacklist token: {}", jti);
    }
  }

  public boolean isBlacklisted(String jti) {
    return blockingTemplate != null && Boolean.TRUE.equals(blockingTemplate.hasKey(key(jti)));
  }

  public Mono<Boolean> isBlacklistedReactive(String jti) {
    return reactiveTemplate != null ? reactiveTemplate.hasKey(key(jti)) : Mono.just(false);
  }
}
