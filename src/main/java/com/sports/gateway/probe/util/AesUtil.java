package com.sports.gateway.probe.util;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

@Slf4j
public class AesUtil {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 4096;
    private static final byte[] SALT = "ProbeAesSalt2024".getBytes(StandardCharsets.UTF_8);
    
    private static final int MAX_CIPHER_TEXT_LENGTH = 1024 * 1024;
    
    // 使用Caffeine LRU缓存替代ConcurrentHashMap，避免内存泄漏
    // 缩短过期时间到10分钟，减少配置更新后旧密钥有效窗口
    private static final Cache<String, SecretKeySpec> keyCache = Caffeine.newBuilder()
            .maximumSize(100)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build();
    
    // ThreadLocal复用Cipher实例，避免频繁创建
    private static final ThreadLocal<Cipher> ENCRYPT_CIPHER = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance(TRANSFORMATION);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create cipher", e);
        }
    });
    
    private static final ThreadLocal<Cipher> DECRYPT_CIPHER = ThreadLocal.withInitial(() -> {
        try {
            return Cipher.getInstance(TRANSFORMATION);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create cipher", e);
        }
    });
    
    // ThreadLocal复用SecureRandom，避免频繁创建
    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);
    
    // 预创建Base64编解码器
    private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
    private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

    public static String encrypt(String plainText, String appId, String key) {
        try {
            SecretKeySpec secretKey = getSecretKey(appId, key);

            byte[] iv = new byte[IV_LENGTH];
            SECURE_RANDOM.get().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = ENCRYPT_CIPHER.get();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, IV_LENGTH);
            System.arraycopy(encrypted, 0, combined, IV_LENGTH, encrypted.length);

            return BASE64_ENCODER.encodeToString(combined);
        } catch (Exception e) {
            log.error("AES encryption error: {}", e.getMessage());
            return null;
        }
    }

    public static String decrypt(String cipherText, String appId, String key) {
        try {
            if (cipherText == null || cipherText.length() > MAX_CIPHER_TEXT_LENGTH) {
                return null;
            }
            byte[] combined = BASE64_DECODER.decode(cipherText);
            if (combined.length <= IV_LENGTH) {
                return null;
            }
            
            byte[] iv = new byte[IV_LENGTH];
            byte[] encrypted = new byte[combined.length - IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
            System.arraycopy(combined, IV_LENGTH, encrypted, 0, encrypted.length);

            SecretKeySpec secretKey = getSecretKey(appId, key);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = DECRYPT_CIPHER.get();
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("AES decryption error: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 清除密钥缓存 - 配置刷新时调用
     * 确保新配置的密钥立即生效，旧密钥立即失效
     */
    public static void clearKeyCache() {
        keyCache.invalidateAll();
        log.info("AES key cache cleared");
    }
    
    /**
     * 移除指定appId的密钥缓存
     */
    public static void invalidateKey(String appId) {
        if (appId != null) {
            // 遍历缓存移除该appId的所有缓存
            keyCache.asMap().keySet().removeIf(k -> k.startsWith(appId + ":"));
        }
    }
    
    private static SecretKeySpec getSecretKey(String appId, String key) {
        // 使用 appId:key 作为缓存键，避免不同appId相同密钥冲突
        String cacheKey = appId + ":" + key;
        SecretKeySpec cached = keyCache.getIfPresent(cacheKey);
        if (cached != null) {
            return cached;
        }
        
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(key.toCharArray(), SALT, ITERATION_COUNT, KEY_LENGTH);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            SecretKeySpec secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
            keyCache.put(cacheKey, secretKey);
            return secretKey;
        } catch (Exception e) {
            log.error("Key derivation error: {}", e.getMessage());
            byte[] fallbackKey = new byte[32];
            byte[] inputBytes = key.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(inputBytes, 0, fallbackKey, 0, Math.min(inputBytes.length, 32));
            return new SecretKeySpec(fallbackKey, ALGORITHM);
        }
    }
}
