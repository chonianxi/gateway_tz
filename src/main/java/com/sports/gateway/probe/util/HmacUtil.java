package com.sports.gateway.probe.util;

import lombok.extern.slf4j.Slf4j;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;

@Slf4j
public class HmacUtil {

    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    
    // 缓存SecretKeySpec，避免每次创建 (CPU优化)
    // 缩短过期时间到10分钟，减少配置更新后旧密钥有效窗口
    private static final Cache<String, SecretKeySpec> SECRET_KEY_CACHE = Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();
    
    // ThreadLocal复用Mac实例
    private static final ThreadLocal<Mac> MAC_INSTANCE = ThreadLocal.withInitial(() -> {
        try {
            return Mac.getInstance(HMAC_SHA256);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create Mac instance", e);
        }
    });
    
    // ThreadLocal复用MessageDigest实例
    private static final ThreadLocal<MessageDigest> SHA256_DIGEST = ThreadLocal.withInitial(() -> {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new RuntimeException("Failed to create MessageDigest instance", e);
        }
    });

    public static String generateHmac(String ts, String nonce, String bodyHash, String secret) {
        try {
            String input = ts + nonce + bodyHash;
            
            Mac mac = MAC_INSTANCE.get();
            SecretKeySpec secretKeySpec = getSecretKeySpec(secret);
            mac.init(secretKeySpec);
            
            byte[] hmacBytes = mac.doFinal(input.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hmacBytes);
        } catch (Exception e) {
            log.error("HMAC generation error: {}", e.getMessage());
            return null;
        }
    }

    public static boolean validateHmac(String ts, String nonce, String bodyHash, 
                                       String providedHmac, String secret) {
        String calculatedHmac = generateHmac(ts, nonce, bodyHash, secret);
        if (calculatedHmac == null) {
            return false;
        }
        return MessageDigest.isEqual(
                calculatedHmac.getBytes(StandardCharsets.UTF_8),
                providedHmac.getBytes(StandardCharsets.UTF_8)
        );
    }

    public static String sha256Hash(byte[] data) {
        try {
            MessageDigest digest = SHA256_DIGEST.get();
            digest.reset();
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (Exception e) {
            log.error("SHA256 hash error: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 清除HMAC密钥缓存 - 配置刷新时调用
     */
    public static void clearKeyCache() {
        SECRET_KEY_CACHE.invalidateAll();
        log.info("HMAC key cache cleared");
    }
    
    // 缓存SecretKeySpec，避免重复创建 (CPU优化)
    private static SecretKeySpec getSecretKeySpec(String secret) {
        return SECRET_KEY_CACHE.get(secret, k -> 
                new SecretKeySpec(k.getBytes(StandardCharsets.UTF_8), HMAC_SHA256));
    }
    
    // 优化: 使用char数组替代String.format，性能提升约10倍
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_CHARS[v >>> 4];
            hexChars[i * 2 + 1] = HEX_CHARS[v & 0x0F];
        }
        return new String(hexChars);
    }
}
