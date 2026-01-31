package com.sports.gateway.probe.service;

import com.sports.gateway.config.properties.ProbeProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;

@Slf4j
@Component
public class ProbeIpRateLimitService {

    private static final String LUA_SCRIPT =
            "local key = KEYS[1] " +
            "local limit = tonumber(ARGV[1]) " +
            "local window = tonumber(ARGV[2]) " +
            "local current = redis.call('INCR', key) " +
            "if current == 1 then redis.call('EXPIRE', key, window) end " +
            "if current > limit then return 0 end " +
            "return 1";

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final RedisScript<Long> script;
    private final ProbeProperties probeProperties;

    public ProbeIpRateLimitService(ReactiveRedisTemplate<String, String> redisTemplate,
                                   ProbeProperties probeProperties) {
        this.redisTemplate = redisTemplate;
        this.probeProperties = probeProperties;
        this.script = RedisScript.of(LUA_SCRIPT, Long.class);
    }

    public Mono<Boolean> allowProbeRequest(String ip, String pathType) {
        String key = "probe:ip:limit:" + pathType + ":" + ip;
        
        return redisTemplate.execute(
                script,
                Collections.singletonList(key),
                Arrays.asList(
                        String.valueOf(probeProperties.getIpRateLimitCount()),
                        String.valueOf(probeProperties.getIpRateLimitWindowSeconds())
                )
        ).next().map(result -> result != null && result == 1L)
         .defaultIfEmpty(false)
         .onErrorResume(e -> {
             log.error("Rate limit check error for IP: {}, error: {}", ip, e.getMessage());
             return Mono.just(false);
         });
    }
}
