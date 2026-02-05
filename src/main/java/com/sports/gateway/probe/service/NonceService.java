package com.sports.gateway.probe.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.sports.gateway.config.properties.ProbeProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Slf4j
@Component
public class NonceService {

    private static final String NONCE_KEY_PREFIX = "probe:nonce:";

    private final StringRedisTemplate redisTemplate;
    private final ProbeProperties probeProperties;
    private Cache<String, Boolean> localCache;

    public NonceService(StringRedisTemplate redisTemplate,
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

    public boolean tryUseNonceSync(String nonce) {
        try {
            if (nonce == null || nonce.length() > 64) {
                return false;
            }

            Boolean localResult = localCache.getIfPresent(nonce);
            if (Boolean.TRUE.equals(localResult)) {
                return false;
            }

            String key = NONCE_KEY_PREFIX + nonce;
            Boolean success = redisTemplate.opsForValue().setIfAbsent(key, "1", 
                    probeProperties.getNonceCacheExpireMinutes(), TimeUnit.MINUTES);
            
            if (Boolean.TRUE.equals(success)) {
                localCache.put(nonce, true);
                return true;
            }
            localCache.put(nonce, true);
            return false;
        } catch (Exception e) {
            log.error("Error using nonce atomically: {}, error: {}", nonce, e.getMessage());
            return false;
        }
    }
}
