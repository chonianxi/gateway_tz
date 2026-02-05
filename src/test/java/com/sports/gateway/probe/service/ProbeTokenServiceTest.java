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
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("探针Token服务测试")
class ProbeTokenServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;
    
    @Mock
    private ValueOperations<String, String> valueOps;

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

        String token = tokenService.generateTokenSync("ios", "device-001", "192.168.1.1", "app001");
        
        assertNotNull(token);
        assertEquals(32, token.length());
    }

    @Test
    @DisplayName("生成Token - Redis异常返回null")
    void generateToken_redisError_returnsNull() {
        when(redisTemplate.opsForValue()).thenThrow(new RuntimeException("Redis error"));

        String token = tokenService.generateTokenSync("ios", "device-001", "192.168.1.1", "app001");
        
        assertNull(token);
    }

    @Test
    @DisplayName("验证Token - 成功")
    void validateToken_success() {
        ProbeTokenInfo tokenInfo = new ProbeTokenInfo();
        tokenInfo.setToken("test-token");
        tokenInfo.setPlatform("ios");
        tokenInfo.setDeviceId("device-001");
        tokenInfo.setClientIp("192.168.1.1");
        tokenInfo.setAppId("app001");
        tokenInfo.setCreatedAt(System.currentTimeMillis());

        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(JSON.toJSONString(tokenInfo));
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(), any()))
                .thenReturn(1L);

        boolean result = tokenService.validateTokenSync("test-token", "192.168.1.1", "app001");
        
        assertTrue(result);
    }

    @Test
    @DisplayName("验证Token - Token不存在")
    void validateToken_notFound() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(null);

        boolean result = tokenService.validateTokenSync("non-existent-token", "192.168.1.1", "app001");
        
        assertFalse(result);
    }

    @Test
    @DisplayName("验证Token - IP不匹配")
    void validateToken_ipMismatch() {
        ProbeTokenInfo tokenInfo = new ProbeTokenInfo();
        tokenInfo.setToken("test-token");
        tokenInfo.setPlatform("ios");
        tokenInfo.setDeviceId("device-001");
        tokenInfo.setClientIp("192.168.1.1");
        tokenInfo.setAppId("app001");
        tokenInfo.setCreatedAt(System.currentTimeMillis());

        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(JSON.toJSONString(tokenInfo));

        boolean result = tokenService.validateTokenSync("test-token", "10.0.0.1", "app001");
        
        assertFalse(result);
    }

    @Test
    @DisplayName("验证Token - 超过限流")
    void validateToken_rateLimited() {
        ProbeTokenInfo tokenInfo = new ProbeTokenInfo();
        tokenInfo.setToken("test-token");
        tokenInfo.setPlatform("ios");
        tokenInfo.setDeviceId("device-001");
        tokenInfo.setClientIp("192.168.1.1");
        tokenInfo.setAppId("app001");
        tokenInfo.setCreatedAt(System.currentTimeMillis());

        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(anyString())).thenReturn(JSON.toJSONString(tokenInfo));
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any(), any()))
                .thenReturn(0L);

        boolean result = tokenService.validateTokenSync("test-token", "192.168.1.1", "app001");
        
        assertFalse(result);
    }

    @Test
    @DisplayName("验证Token - Token为null")
    void validateToken_null() {
        boolean result = tokenService.validateTokenSync(null, "192.168.1.1", "app001");
        
        assertFalse(result);
    }

    @Test
    @DisplayName("验证Token - Token过长")
    void validateToken_tooLong() {
        String longToken = "a".repeat(100);
        
        boolean result = tokenService.validateTokenSync(longToken, "192.168.1.1", "app001");
        
        assertFalse(result);
    }
}
