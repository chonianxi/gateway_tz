package com.sports.gateway.probe.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sports.gateway.config.properties.ProbeProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class NonceService {

    private static final String NONCE_KEY_PREFIX = "probe:nonce:";

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final ProbeProperties probeProperties;
    private Cache<String, Boolean> localCache;

    public NonceService(ReactiveRedisTemplate<String, String> redisTemplate,
                        ProbeProperties probeProperties) {
        this.redisTemplate = redisTemplate;
        this.probeProperties = probeProperties;
    }

    @PostConstruct
    public void init() {
        this.localCache = Caffeine.newBuilder()
                .maximumSize(probeProperties.getNonceCacheSize())
                .expireAfterWrite(probeProperties.getNonceCacheExpireMinutes(), TimeUnit.MINUTES)
                .build();
    }

    public Mono<Boolean> tryUseNonce(String nonce) {
        if (nonce == null || nonce.length() > 64) {
            return Mono.just(false);
        }

        Boolean localResult = localCache.getIfPresent(nonce);
        if (Boolean.TRUE.equals(localResult)) {
            return Mono.just(false);
        }

        String key = NONCE_KEY_PREFIX + nonce;
        return redisTemplate.opsForValue()
                .setIfAbsent(key, "1", Duration.ofMinutes(probeProperties.getNonceCacheExpireMinutes()))
                .map(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        localCache.put(nonce, true);
                        return true;
                    }
                    localCache.put(nonce, true);
                    return false;
                })
                .onErrorResume(e -> {
                    log.error("Error using nonce atomically: {}, error: {}", nonce, e.getMessage());
                    return Mono.just(false);
                });
    }
}
