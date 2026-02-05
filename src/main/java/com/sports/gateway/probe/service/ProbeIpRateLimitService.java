package com.sports.gateway.probe.service;

import com.sports.gateway.config.properties.ProbeProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;

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

    private final StringRedisTemplate redisTemplate;
    private final RedisScript<Long> script;
    private final ProbeProperties probeProperties;

    public ProbeIpRateLimitService(StringRedisTemplate redisTemplate,
                                   ProbeProperties probeProperties) {
        this.redisTemplate = redisTemplate;
        this.probeProperties = probeProperties;
        this.script = RedisScript.of(LUA_SCRIPT, Long.class);
    }

    public boolean allowProbeRequestSync(String ip, String pathType) {
        try {
            String key = "probe:ip:limit:" + pathType + ":" + ip;
            List<String> keys = Collections.singletonList(key);
            
            Long result = redisTemplate.execute(
                    script,
                    keys,
                    String.valueOf(probeProperties.getIpRateLimitCount()),
                    String.valueOf(probeProperties.getIpRateLimitWindowSeconds())
            );
            
            return result != null && result == 1L;
        } catch (Exception e) {
            log.error("Rate limit check error for IP: {}, error: {}", ip, e.getMessage());
            return false;
        }
    }
}
