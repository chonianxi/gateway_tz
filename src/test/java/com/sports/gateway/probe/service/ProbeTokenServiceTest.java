package com.sports.gateway.probe.service;

import com.alibaba.fastjson.JSON;
import com.sports.gateway.config.properties.ProbeProperties;
import com.sports.gateway.probe.dto.ProbeTokenInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.ReactiveValueOperations;
import org.springframework.data.redis.core.script.RedisScript;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("探针Token服务测试")
class ProbeTokenServiceTest {

    @Mock
    private ReactiveRedisTemplate<String, String> redisTemplate;
    
    @Mock
    private ReactiveValueOperations<String, String> valueOps;

    private ProbeProperties probeProperties;
    private ProbeTokenService tokenService;

    @BeforeEach
    void setUp() {
        probeProperties = new ProbeProperties();
        probeProperties.setTokenTtlMinutes(30);
        probeProperties.setTokenMaxRequestsPerWindow(100);
        probeProperties.setTokenRequestWindowMinutes(5);
        
        tokenService = new ProbeTokenService(redisTemplate, probeProperties);
    }

    @Test
    @DisplayName("生成Token - 成功")
    void generateToken_success() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                .thenReturn(Mono.just(true));

        StepVerifier.create(tokenService.generateToken("ios", "device-001", "192.168.1.1"))
                .expectNextMatches(token -> token != null && token.length() == 32)
                .verifyComplete();
    }

    @Test
    @DisplayName("生成Token - Redis异常返回空")
    void generateToken_redisError_returnsEmpty() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.set(anyString(), anyString(), any(Duration.class)))
                .thenReturn(Mono.error(new RuntimeException("Redis error")));

        StepVerifier.create(tokenService.generateToken("ios", "device-001", "192.168.1.1"))
                .verifyComplete();
    }

    @Test
    @DisplayName("验证Token - 成功")
    void validateToken_success() {
        ProbeTokenInfo tokenInfo = new ProbeTokenInfo();
        tokenInfo.setToken("test-token");
        tokenInfo.setPlatform("ios");
        tokenInfo.setDeviceId("device-001");
        tokenInfo.setClientIp("192.168.1.1");
        tokenInfo.setCreatedAt(System.currentTimeMillis());

        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(Mono.just(JSON.toJSONString(tokenInfo)));
        when(redisTemplate.execute(any(RedisScript.class), anyList(), anyList()))
                .thenReturn(Flux.just(1L));

        StepVerifier.create(tokenService.validateToken("test-token", "192.168.1.1"))
                .expectNextMatches(info -> info.getToken().equals("test-token"))
                .verifyComplete();
    }

    @Test
    @DisplayName("验证Token - Token不存在")
    void validateToken_notFound() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(Mono.empty());

        StepVerifier.create(tokenService.validateToken("non-existent-token"))
                .verifyComplete();
    }

    @Test
    @DisplayName("验证Token - IP不匹配")
    void validateToken_ipMismatch() {
        ProbeTokenInfo tokenInfo = new ProbeTokenInfo();
        tokenInfo.setToken("test-token");
        tokenInfo.setPlatform("ios");
        tokenInfo.setDeviceId("device-001");
        tokenInfo.setClientIp("192.168.1.1");
        tokenInfo.setCreatedAt(System.currentTimeMillis());

        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(Mono.just(JSON.toJSONString(tokenInfo)));

        StepVerifier.create(tokenService.validateToken("test-token", "10.0.0.1"))
                .verifyComplete();
    }

    @Test
    @DisplayName("验证Token - 超过限流")
    void validateToken_rateLimited() {
        ProbeTokenInfo tokenInfo = new ProbeTokenInfo();
        tokenInfo.setToken("test-token");
        tokenInfo.setPlatform("ios");
        tokenInfo.setDeviceId("device-001");
        tokenInfo.setClientIp("192.168.1.1");
        tokenInfo.setCreatedAt(System.currentTimeMillis());

        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(Mono.just(JSON.toJSONString(tokenInfo)));
        when(redisTemplate.execute(any(RedisScript.class), anyList(), anyList()))
                .thenReturn(Flux.just(0L));

        StepVerifier.create(tokenService.validateToken("test-token", "192.168.1.1"))
                .verifyComplete();
    }

    @Test
    @DisplayName("验证Token - Token为null")
    void validateToken_null() {
        StepVerifier.create(tokenService.validateToken(null))
                .verifyComplete();
    }

    @Test
    @DisplayName("验证Token - Token过长")
    void validateToken_tooLong() {
        String longToken = "a".repeat(100);
        
        StepVerifier.create(tokenService.validateToken(longToken))
                .verifyComplete();
    }
}
