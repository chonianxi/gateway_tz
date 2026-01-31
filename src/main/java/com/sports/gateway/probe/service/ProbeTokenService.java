package com.sports.gateway.probe.service;

import cn.hutool.core.util.IdUtil;
import com.alibaba.fastjson.JSON;
import com.sports.gateway.config.properties.ProbeProperties;
import com.sports.gateway.probe.dto.ProbeTokenInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;

@Slf4j
@Component
public class ProbeTokenService {

    private static final String TOKEN_KEY_PREFIX = "probe:token:";
    private static final String TOKEN_COUNT_KEY_PREFIX = "probe:token:count:";

    private static final String INCREMENT_SCRIPT =
            "local key = KEYS[1] " +
            "local limit = tonumber(ARGV[1]) " +
            "local window = tonumber(ARGV[2]) " +
            "local current = redis.call('INCR', key) " +
            "if current == 1 then redis.call('EXPIRE', key, window) end " +
            "if current > limit then return 0 end " +
            "return 1";

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final RedisScript<Long> incrementScript;
    private final ProbeProperties probeProperties;

    public ProbeTokenService(ReactiveRedisTemplate<String, String> redisTemplate,
                             ProbeProperties probeProperties) {
        this.redisTemplate = redisTemplate;
        this.probeProperties = probeProperties;
        this.incrementScript = RedisScript.of(INCREMENT_SCRIPT, Long.class);
    }

    public Mono<String> generateToken(String platform, String deviceId, String clientIp) {
        String token = IdUtil.fastSimpleUUID();
        String key = TOKEN_KEY_PREFIX + token;

        ProbeTokenInfo tokenInfo = new ProbeTokenInfo();
        tokenInfo.setToken(token);
        tokenInfo.setPlatform(platform);
        tokenInfo.setDeviceId(deviceId);
        tokenInfo.setClientIp(clientIp);
        tokenInfo.setCreatedAt(System.currentTimeMillis());

        return redisTemplate.opsForValue()
                .set(key, JSON.toJSONString(tokenInfo), 
                     Duration.ofMinutes(probeProperties.getTokenTtlMinutes()))
                .thenReturn(token)
                .onErrorResume(e -> {
                    log.error("Error generating token: {}", e.getMessage());
                    return Mono.empty();
                });
    }

    public Mono<ProbeTokenInfo> validateToken(String token) {
        return validateToken(token, null);
    }

    public Mono<ProbeTokenInfo> validateToken(String token, String clientIp) {
        if (token == null || token.length() > 64) {
            return Mono.empty();
        }

        String key = TOKEN_KEY_PREFIX + token;
        String countKey = TOKEN_COUNT_KEY_PREFIX + token;

        return redisTemplate.opsForValue().get(key)
                .flatMap(tokenInfoJson -> {
                    if (tokenInfoJson == null) {
                        return Mono.empty();
                    }
                    
                    ProbeTokenInfo tokenInfo = JSON.parseObject(tokenInfoJson, ProbeTokenInfo.class);
                    if (tokenInfo == null) {
                        return Mono.empty();
                    }

                    if (clientIp != null && tokenInfo.getClientIp() != null 
                            && !clientIp.equals(tokenInfo.getClientIp())) {
                        log.warn("Token IP mismatch: expected {}, got {}", 
                                tokenInfo.getClientIp(), clientIp);
                        return Mono.empty();
                    }
                    
                    return redisTemplate.execute(
                            incrementScript,
                            Collections.singletonList(countKey),
                            Arrays.asList(
                                    String.valueOf(probeProperties.getTokenMaxRequestsPerWindow()),
                                    String.valueOf(probeProperties.getTokenRequestWindowMinutes() * 60)
                            )
                    ).next().flatMap(result -> {
                        if (result != null && result == 1L) {
                            return Mono.just(tokenInfo);
                        }
                        return Mono.empty();
                    });
                })
                .onErrorResume(e -> {
                    log.error("Error validating token: {}", e.getMessage());
                    return Mono.empty();
                });
    }
}
