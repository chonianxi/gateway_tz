package com.sports.gateway.probe.service;

import cn.hutool.core.util.IdUtil;
import com.alibaba.fastjson.JSON;
import com.sports.gateway.config.properties.ProbeProperties;
import com.sports.gateway.probe.dto.ProbeTokenInfo;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

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

    private final StringRedisTemplate redisTemplate;
    private final RedisScript<Long> incrementScript;
    private final ProbeProperties probeProperties;

    public ProbeTokenService(StringRedisTemplate redisTemplate,
                             ProbeProperties probeProperties) {
        this.redisTemplate = redisTemplate;
        this.probeProperties = probeProperties;
        this.incrementScript = RedisScript.of(INCREMENT_SCRIPT, Long.class);
    }

    public String generateTokenSync(String platform, String deviceId, String clientIp, String appId) {
        try {
            String token = IdUtil.fastSimpleUUID();
            String key = TOKEN_KEY_PREFIX + appId + ":" + token;

            ProbeTokenInfo tokenInfo = new ProbeTokenInfo();
            tokenInfo.setToken(token);
            tokenInfo.setPlatform(platform);
            tokenInfo.setDeviceId(deviceId);
            tokenInfo.setClientIp(clientIp);
            tokenInfo.setAppId(appId);
            tokenInfo.setCreatedAt(System.currentTimeMillis());

            redisTemplate.opsForValue().set(key, JSON.toJSONString(tokenInfo), 
                    probeProperties.getTokenTtlMinutes(), TimeUnit.MINUTES);
            
            return token;
        } catch (Exception e) {
            log.error("Error generating token: {}", e.getMessage());
            return null;
        }
    }

    public boolean validateTokenSync(String token, String clientIp, String appId) {
        try {
            if (token == null || token.length() > 64) {
                return false;
            }

            String key = TOKEN_KEY_PREFIX + appId + ":" + token;
            String countKey = TOKEN_COUNT_KEY_PREFIX + appId + ":" + token;

            String tokenInfoJson = redisTemplate.opsForValue().get(key);
            if (tokenInfoJson == null) {
                return false;
            }

            ProbeTokenInfo tokenInfo = JSON.parseObject(tokenInfoJson, ProbeTokenInfo.class);
            if (tokenInfo == null) {
                return false;
            }

            if (clientIp != null && tokenInfo.getClientIp() != null 
                    && !clientIp.equals(tokenInfo.getClientIp())) {
                log.warn("Token IP mismatch: expected {}, got {}", tokenInfo.getClientIp(), clientIp);
                return false;
            }

            List<String> keys = Collections.singletonList(countKey);
            Long result = redisTemplate.execute(
                    incrementScript,
                    keys,
                    String.valueOf(probeProperties.getTokenMaxRequestsPerWindow()),
                    String.valueOf(probeProperties.getTokenRequestWindowMinutes() * 60)
            );

            return result != null && result == 1L;
        } catch (Exception e) {
            log.error("Error validating token: {}", e.getMessage());
            return false;
        }
    }
}
