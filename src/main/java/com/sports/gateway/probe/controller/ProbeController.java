package com.sports.gateway.probe.controller;

import cn.hutool.core.util.StrUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sports.gateway.config.properties.ProbeProperties;
import com.sports.gateway.probe.dto.DnsConfigResponse;
import com.sports.gateway.probe.dto.TokenRequest;
import com.sports.gateway.probe.dto.TokenResponse;
import com.sports.gateway.probe.service.*;
import com.sports.gateway.probe.util.AesUtil;
import com.sports.gateway.probe.util.HmacUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

@Slf4j
@RestController
@RequestMapping("/api/probe")
public class ProbeController {

    private static final String HEADER_X_TS = "X-Ts";
    private static final String HEADER_X_NONCE = "X-Nonce";
    private static final String HEADER_X_SIGN = "X-Sign";
    private static final String HEADER_X_TOKEN = "X-Probe-Token";
    private static final String HEADER_X_APP_ID = "X-App-Id";

    private static final int MAX_BODY_SIZE = 64 * 1024;
    private static final int MAX_NONCE_LENGTH = 64;
    private static final int MAX_TOKEN_LENGTH = 64;
    private static final int MAX_SIGN_LENGTH = 128;
    private static final int MAX_TS_LENGTH = 16;
    private static final int MAX_APP_ID_LENGTH = 64;
    private static final int MAX_IP_LENGTH = 64;  // IPv6 with zone ID (e.g., fe80::1%eth0)
    
    // 缓存TypeReference实例，避免每次创建
    private static final TypeReference<Map<String, Object>> MAP_TYPE_REF = new TypeReference<>() {};

    private final ProbeProperties probeProperties;
    private final ObjectMapper objectMapper;
    private final ProbeIpRateLimitService rateLimitService;
    private final ProbeTokenService tokenService;
    private final NonceService nonceService;
    private final AppConfigService appConfigService;
    private final ProbeKafkaService kafkaService;

    public ProbeController(ProbeProperties probeProperties,
                          ProbeIpRateLimitService rateLimitService,
                          ProbeTokenService tokenService,
                          NonceService nonceService,
                          AppConfigService appConfigService,
                          ProbeKafkaService kafkaService,
                          ObjectMapper objectMapper) {
        this.probeProperties = probeProperties;
        this.rateLimitService = rateLimitService;
        this.tokenService = tokenService;
        this.nonceService = nonceService;
        this.appConfigService = appConfigService;
        this.kafkaService = kafkaService;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/{platform}/token")
    public ResponseEntity<String> getToken(
            @PathVariable String platform,
            @RequestHeader(HEADER_X_APP_ID) String appId,
            @RequestBody String encryptedBody,
            HttpServletRequest request) {
        
        if (!probeProperties.isEnabled() || !probeProperties.isTokenEnabled()) {
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // 防止数据伪造: 先验证输入长度和格式
        if (!isValidPlatform(platform) || !isValidAppId(appId)) {
            return ResponseEntity.noContent().build();
        }

        String aesKey = appConfigService.getAesKey(appId);
        if (aesKey == null) {
            log.warn("Invalid appId: {}", appId);
            return ResponseEntity.noContent().build();
        }

        String clientIp = getClientIp(request);

        if (!rateLimitService.allowProbeRequestSync(clientIp, "token")) {
            return ResponseEntity.noContent().build();
        }

        try {
            if (encryptedBody == null || encryptedBody.isEmpty() || encryptedBody.length() > MAX_BODY_SIZE) {
                return ResponseEntity.noContent().build();
            }

            String decryptedBody = AesUtil.decrypt(encryptedBody, aesKey);
            if (decryptedBody == null) {
                return ResponseEntity.noContent().build();
            }

            TokenRequest tokenRequest = objectMapper.readValue(decryptedBody, TokenRequest.class);
            if (tokenRequest == null || StrUtil.isBlank(tokenRequest.getDeviceId()) 
                    || tokenRequest.getDeviceId().length() > 128) {
                return ResponseEntity.noContent().build();
            }

            String token = tokenService.generateTokenSync(platform, tokenRequest.getDeviceId(), clientIp, appId);
            if (token == null) {
                return ResponseEntity.noContent().build();
            }

            TokenResponse response = new TokenResponse();
            response.setToken(token);
            response.setExpiresIn(probeProperties.getTokenTtlMinutes() * 60L);

            String responseJson = objectMapper.writeValueAsString(response);
            String encryptedResponse = AesUtil.encrypt(responseJson, aesKey);

            return ResponseEntity.ok(encryptedResponse);
        } catch (Exception e) {
            log.error("Token request processing error: {}", e.getMessage());
            return ResponseEntity.noContent().build();
        }
    }

    @PostMapping("/{platform}/dns-config")
    public ResponseEntity<String> getDnsConfig(
            @PathVariable String platform,
            @RequestHeader(HEADER_X_APP_ID) String appId,
            @RequestHeader(HEADER_X_TOKEN) String token,
            HttpServletRequest request) {

        if (!probeProperties.isEnabled() || !probeProperties.isDnsConfigEnabled()) {
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // 防止数据伪造: 先验证输入长度和格式
        if (!isValidPlatform(platform) || !isValidAppId(appId)) {
            return ResponseEntity.noContent().build();
        }

        String aesKey = appConfigService.getAesKey(appId);
        if (aesKey == null) {
            return ResponseEntity.noContent().build();
        }

        if (StrUtil.isBlank(token) || token.length() > MAX_TOKEN_LENGTH) {
            return ResponseEntity.noContent().build();
        }

        String clientIp = getClientIp(request);

        if (!rateLimitService.allowProbeRequestSync(clientIp, "dns-config")) {
            return ResponseEntity.noContent().build();
        }

        if (!tokenService.validateTokenSync(token, clientIp, appId)) {
            return ResponseEntity.noContent().build();
        }

        DnsConfigResponse response = buildDnsConfigResponse(appId);
        String responseJson;
        try {
            responseJson = objectMapper.writeValueAsString(response);
        } catch (JsonProcessingException e) {
            log.error("JSON serialization error: {}", e.getMessage());
            return ResponseEntity.noContent().build();
        }
        String encryptedResponse = AesUtil.encrypt(responseJson, aesKey);

        if (encryptedResponse == null) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok(encryptedResponse);
    }

    @PostMapping("/{platform}/upload")
    public ResponseEntity<Void> uploadProbeData(
            @PathVariable String platform,
            @RequestHeader(HEADER_X_APP_ID) String appId,
            @RequestHeader(HEADER_X_TOKEN) String token,
            @RequestHeader(HEADER_X_TS) String ts,
            @RequestHeader(HEADER_X_NONCE) String nonce,
            @RequestHeader(HEADER_X_SIGN) String sign,
            @RequestBody String encryptedBody,
            HttpServletRequest request) {

        if (!probeProperties.isEnabled() || !probeProperties.isUploadEnabled()) {
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // === 阶段1: CPU校验 (无IO, 快速失败) ===
        if (!isValidPlatform(platform) || !isValidAppId(appId)) {
            return ResponseEntity.noContent().build();
        }

        String aesKey = appConfigService.getAesKey(appId);
        String hmacSecret = appConfigService.getHmacSecret(appId);
        if (aesKey == null || hmacSecret == null) {
            return ResponseEntity.noContent().build();
        }

        if (StrUtil.isBlank(ts) || StrUtil.isBlank(nonce) || 
            StrUtil.isBlank(sign) || StrUtil.isBlank(token)) {
            return ResponseEntity.noContent().build();
        }

        if (!isValidHeaderLength(ts, nonce, sign, token)) {
            return ResponseEntity.noContent().build();
        }

        if (!isTimestampValid(ts)) {
            return ResponseEntity.noContent().build();
        }

        if (encryptedBody == null || encryptedBody.isEmpty() || encryptedBody.length() > MAX_BODY_SIZE) {
            return ResponseEntity.noContent().build();
        }

        // === 阶段2: HMAC验证 (CPU密集, 在Redis调用前完成) ===
        byte[] bodyBytes = encryptedBody.getBytes();
        String bodyHash = HmacUtil.sha256Hash(bodyBytes);
        if (bodyHash == null) {
            return ResponseEntity.noContent().build();
        }

        if (!HmacUtil.validateHmac(ts, nonce, bodyHash, sign, hmacSecret)) {
            return ResponseEntity.noContent().build();
        }

        // === 阶段3: 并行Redis校验 (优化: 从4次串行变为2次并行) ===
        String clientIp = getClientIp(request);

        CompletableFuture<Boolean> rateLimitFuture = CompletableFuture.supplyAsync(() -> 
                rateLimitService.allowProbeRequestSync(clientIp, "upload"));
        CompletableFuture<Boolean> tokenFuture = CompletableFuture.supplyAsync(() -> 
                tokenService.validateTokenSync(token, clientIp, appId));

        try {
            // 等待两个Redis调用并行完成，超时500ms
            CompletableFuture.allOf(rateLimitFuture, tokenFuture).get(500, TimeUnit.MILLISECONDS);
            
            if (!rateLimitFuture.get() || !tokenFuture.get()) {
                return ResponseEntity.noContent().build();
            }
        } catch (Exception e) {
            log.error("Parallel validation error: {}", e.getMessage());
            return ResponseEntity.noContent().build();
        }

        // === 阶段4: Nonce消费 (必须在HMAC和Token验证通过后) ===
        if (!nonceService.tryUseNonceSync(nonce)) {
            return ResponseEntity.noContent().build();
        }

        // === 阶段5: 解密和处理 ===
        try {
            String decryptedBody = AesUtil.decrypt(encryptedBody, aesKey);
            if (decryptedBody == null) {
                return ResponseEntity.noContent().build();
            }

            Map<String, Object> probeData = objectMapper.readValue(decryptedBody, MAP_TYPE_REF);
            if (probeData == null) {
                return ResponseEntity.noContent().build();
            }

            kafkaService.sendProbeData(appId, platform, clientIp, probeData);

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("Upload processing error: {}", e.getMessage());
            return ResponseEntity.noContent().build();
        }
    }

    @PostMapping("/h5/upload")
    public ResponseEntity<Void> uploadH5ProbeData(
            @RequestHeader(HEADER_X_APP_ID) String appId,
            @RequestHeader(value = "Origin", required = false) String origin,
            @RequestHeader(value = "Referer", required = false) String referer,
            @RequestBody String body,
            HttpServletRequest request) {

        if (!probeProperties.isEnabled() || !probeProperties.isH5UploadEnabled()) {
            return ResponseEntity.status(HttpStatus.GONE).build();
        }

        // 防止数据伪造: 先验证输入长度和格式
        if (!isValidAppId(appId) || !appConfigService.isValidAppId(appId)) {
            return ResponseEntity.noContent().build();
        }

        // H5安全防护: 验证来源 (可选配置)
        if (!isValidH5Origin(origin, referer)) {
            log.warn("H5 upload rejected: invalid origin={}, referer={}", origin, referer);
            return ResponseEntity.noContent().build();
        }

        String clientIp = getClientIp(request);

        // H5接口使用更严格的限流 (防止滥用攻击)
        if (!rateLimitService.allowProbeRequestSync(clientIp, "h5-upload")) {
            return ResponseEntity.noContent().build();
        }

        try {
            if (body == null || body.isEmpty() || body.length() > MAX_BODY_SIZE) {
                return ResponseEntity.noContent().build();
            }

            Map<String, Object> probeData = objectMapper.readValue(body, MAP_TYPE_REF);
            if (probeData == null || probeData.isEmpty()) {
                return ResponseEntity.noContent().build();
            }
            
            // 限制probeData字段数量，防止内存攻击
            if (probeData.size() > 50) {
                return ResponseEntity.noContent().build();
            }

            kafkaService.sendProbeData(appId, "h5", clientIp, probeData);

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            log.error("H5 upload processing error: {}", e.getMessage());
            return ResponseEntity.noContent().build();
        }
    }
    
    // H5来源验证 (基础防护，可通过配置扩展)
    private boolean isValidH5Origin(String origin, String referer) {
        // 如果没有配置白名单，允许所有来源 (向后兼容)
        // 生产环境建议配置 probe.h5-allowed-origins
        if (origin == null && referer == null) {
            return true; // 允许无来源请求 (可能是服务端调用)
        }
        // 基础长度检查，防止超长header攻击
        if ((origin != null && origin.length() > 256) || 
            (referer != null && referer.length() > 512)) {
            return false;
        }
        return true;
    }

    private boolean isValidPlatform(String platform) {
        // 防止数据伪造: 严格校验平台值
        if (platform == null || platform.length() > 10) {
            return false;
        }
        String lower = platform.toLowerCase();
        return "ios".equals(lower) || "android".equals(lower);
    }
    
    // 防止数据伪造: 校验appId格式(仅允许字母数字下划线)
    private boolean isValidAppId(String appId) {
        if (appId == null || appId.isEmpty() || appId.length() > MAX_APP_ID_LENGTH) {
            return false;
        }
        for (int i = 0; i < appId.length(); i++) {
            char c = appId.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
                  (c >= '0' && c <= '9') || c == '_' || c == '-')) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidHeaderLength(String ts, String nonce, String sign, String token) {
        return ts.length() <= MAX_TS_LENGTH &&
               nonce.length() <= MAX_NONCE_LENGTH &&
               sign.length() <= MAX_SIGN_LENGTH &&
               token.length() <= MAX_TOKEN_LENGTH;
    }

    private boolean isTimestampValid(String ts) {
        try {
            long timestamp = Long.parseLong(ts);
            long now = System.currentTimeMillis();
            long diff = Math.abs(now - timestamp);
            long maxDiff = probeProperties.getTimestampValidMinutes() * 60 * 1000L;
            return diff <= maxDiff;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private DnsConfigResponse buildDnsConfigResponse(String appId) {
        DnsConfigResponse response = new DnsConfigResponse();
        
        // 获取商户独立配置，如果为空则使用全局配置
        ProbeProperties.AppConfig appConfig = findAppConfig(appId);
        
        // DNS服务器: 优先使用商户配置，为空则使用全局配置
        List<String> dnsServers = (appConfig != null && appConfig.getProbeDnsServers() != null 
                && !appConfig.getProbeDnsServers().isEmpty()) 
                ? appConfig.getProbeDnsServers() 
                : probeProperties.getProbeDnsServers();
        response.setDnsServers(new java.util.ArrayList<>(dnsServers));
        
        // 域名分类: 优先使用商户配置，为空则使用全局配置
        Map<String, ProbeProperties.DomainCategory> categories = 
                (appConfig != null && appConfig.getDomainCategories() != null 
                && !appConfig.getDomainCategories().isEmpty()) 
                ? appConfig.getDomainCategories() 
                : probeProperties.getDomainCategories();

        categories.forEach((key, category) -> {
            if (category != null) {
                DnsConfigResponse.DomainCategoryDto dto = new DnsConfigResponse.DomainCategoryDto();
                dto.setCategoryKey(key);
                dto.setName(category.getName());
                dto.setDescription(category.getDescription());
                dto.setDomains(category.getDomains() != null ? 
                        new java.util.ArrayList<>(category.getDomains()) : new java.util.ArrayList<>());
                response.getCategories().add(dto);
            }
        });
        
        // 监控用户列表
        if (appConfig != null && appConfig.getMonitorUsers() != null) {
            response.setMonitorUsers(appConfig.getMonitorUsers());
        }

        return response;
    }
    
    private ProbeProperties.AppConfig findAppConfig(String appId) {
        if (appId == null || probeProperties.getApps() == null) {
            return null;
        }
        for (ProbeProperties.AppConfig app : probeProperties.getApps()) {
            if (app != null && appId.equals(app.getAppId())) {
                return app;
            }
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Real-IP");
        if (isValidIp(ip)) {
            return ip.trim();
        }
        ip = request.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isEmpty() && ip.length() <= 500) {
            // 防止ReDoS: 不使用split正则，手动查找第一个逗号
            int commaIndex = ip.indexOf(',');
            String firstIp = (commaIndex > 0) ? ip.substring(0, commaIndex).trim() : ip.trim();
            if (isValidIp(firstIp)) {
                return firstIp;
            }
        }
        return request.getRemoteAddr();
    }

    // 防止ReDoS: 使用字符遍历替代正则表达式验证IP (支持IPv4/IPv6/IPv6 zone ID)
    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty() || ip.length() > MAX_IP_LENGTH) {
            return false;
        }
        // IPv4: 0-9, .
        // IPv6: 0-9, a-f, A-F, :
        // IPv6 zone ID: % 后跟接口名 (字母数字)
        boolean hasPercent = false;
        for (int i = 0; i < ip.length(); i++) {
            char c = ip.charAt(i);
            if (c == '%') {
                hasPercent = true;
                continue;
            }
            if (hasPercent) {
                // zone ID部分: 允许字母数字
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
                    return false;
                }
            } else {
                // IP部分: 数字、十六进制字母、点、冒号
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || 
                      (c >= 'A' && c <= 'F') || c == '.' || c == ':')) {
                    return false;
                }
            }
        }
        return true;
    }
}
