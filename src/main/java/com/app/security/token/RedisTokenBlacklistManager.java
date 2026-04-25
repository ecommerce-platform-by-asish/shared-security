package com.app.security.token;

import java.time.Duration;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.Nullable;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import reactor.core.publisher.Mono;

@Slf4j
@RequiredArgsConstructor
public class RedisTokenBlacklistManager {

  private static final String BLACKLIST_PREFIX = "jwt:blacklist:";

  private final @Nullable StringRedisTemplate blockingTemplate;
  private final @Nullable ReactiveStringRedisTemplate reactiveTemplate;

  private static String key(String jti) {
    return BLACKLIST_PREFIX + jti;
  }

  public void blacklist(String jti, Duration duration) {
    Optional.ofNullable(blockingTemplate)
        .ifPresentOrElse(
            t -> t.opsForValue().set(key(jti), "true", duration),
            () ->
                log.warn("Blocking RedisTemplate not available. Cannot blacklist token: {}", jti));
  }

  public boolean isBlacklisted(String jti) {
    return Optional.ofNullable(blockingTemplate)
        .map(t -> Boolean.TRUE.equals(t.hasKey(key(jti))))
        .orElse(false);
  }

  public Mono<Boolean> isBlacklistedReactive(String jti) {
    return Optional.ofNullable(reactiveTemplate)
        .map(t -> t.hasKey(key(jti)))
        .orElse(Mono.just(false));
  }
}
