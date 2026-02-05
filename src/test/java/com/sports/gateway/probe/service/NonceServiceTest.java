package com.sports.gateway.probe.service;

import com.sports.gateway.config.properties.ProbeProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("Nonce服务测试")
class NonceServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;
    
    @Mock
    private ValueOperations<String, String> valueOps;

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
        when(valueOps.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class)))
                .thenReturn(true);

        boolean result = nonceService.tryUseNonceSync("test-nonce-001");
        
        assertTrue(result);
    }

    @Test
    @DisplayName("重复使用Nonce - Redis返回false")
    void tryUseNonce_duplicate_redisReturnsFalse() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class)))
                .thenReturn(false);

        boolean result = nonceService.tryUseNonceSync("test-nonce-002");
        
        assertFalse(result);
    }

    @Test
    @DisplayName("重复使用Nonce - 本地缓存命中")
    void tryUseNonce_duplicate_localCacheHit() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.setIfAbsent(anyString(), anyString(), anyLong(), any(TimeUnit.class)))
                .thenReturn(true);

        nonceService.tryUseNonceSync("test-nonce-003");

        boolean result = nonceService.tryUseNonceSync("test-nonce-003");
        
        assertFalse(result);
    }

    @Test
    @DisplayName("Nonce为null - 返回false")
    void tryUseNonce_null_returnsFalse() {
        boolean result = nonceService.tryUseNonceSync(null);
        
        assertFalse(result);
    }

    @Test
    @DisplayName("Nonce过长 - 返回false")
    void tryUseNonce_tooLong_returnsFalse() {
        String longNonce = "a".repeat(100);
        
        boolean result = nonceService.tryUseNonceSync(longNonce);
        
        assertFalse(result);
    }

    @Test
    @DisplayName("Redis异常 - 返回false")
    void tryUseNonce_redisError_returnsFalse() {
        when(redisTemplate.opsForValue()).thenThrow(new RuntimeException("Redis connection failed"));

        boolean result = nonceService.tryUseNonceSync("test-nonce-004");
        
        assertFalse(result);
    }
}
