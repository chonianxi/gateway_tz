package com.sports.gateway.probe.service;

import com.sports.gateway.config.properties.ProbeProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.ReactiveValueOperations;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Nonce服务测试")
class NonceServiceTest {

    @Mock
    private ReactiveRedisTemplate<String, String> redisTemplate;
    
    @Mock
    private ReactiveValueOperations<String, String> valueOps;

    private ProbeProperties probeProperties;
    private NonceService nonceService;

    @BeforeEach
    void setUp() {
        probeProperties = new ProbeProperties();
        probeProperties.setNonceCacheSize(10000);
        probeProperties.setNonceCacheExpireMinutes(10);
        
        nonceService = new NonceService(redisTemplate, probeProperties);
        nonceService.init();
    }

    @Test
    @DisplayName("首次使用Nonce - 成功")
    void tryUseNonce_firstTime_success() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(anyString(), anyString(), any(Duration.class)))
                .thenReturn(Mono.just(true));

        StepVerifier.create(nonceService.tryUseNonce("test-nonce-001"))
                .expectNext(true)
                .verifyComplete();
    }

    @Test
    @DisplayName("重复使用Nonce - Redis返回false")
    void tryUseNonce_duplicate_redisReturnsFalse() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(anyString(), anyString(), any(Duration.class)))
                .thenReturn(Mono.just(false));

        StepVerifier.create(nonceService.tryUseNonce("test-nonce-002"))
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    @DisplayName("重复使用Nonce - 本地缓存命中")
    void tryUseNonce_duplicate_localCacheHit() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(anyString(), anyString(), any(Duration.class)))
                .thenReturn(Mono.just(true));

        nonceService.tryUseNonce("test-nonce-003").block();

        StepVerifier.create(nonceService.tryUseNonce("test-nonce-003"))
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    @DisplayName("Nonce为null - 返回false")
    void tryUseNonce_null_returnsFalse() {
        StepVerifier.create(nonceService.tryUseNonce(null))
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    @DisplayName("Nonce过长 - 返回false")
    void tryUseNonce_tooLong_returnsFalse() {
        String longNonce = "a".repeat(100);
        
        StepVerifier.create(nonceService.tryUseNonce(longNonce))
                .expectNext(false)
                .verifyComplete();
    }

    @Test
    @DisplayName("Redis异常 - 返回false")
    void tryUseNonce_redisError_returnsFalse() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(anyString(), anyString(), any(Duration.class)))
                .thenReturn(Mono.error(new RuntimeException("Redis connection failed")));

        StepVerifier.create(nonceService.tryUseNonce("test-nonce-004"))
                .expectNext(false)
                .verifyComplete();
    }
}
