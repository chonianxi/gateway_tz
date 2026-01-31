package com.sports.gateway.probe.util;

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
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class AesUtil {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final int ITERATION_COUNT = 65536;
    private static final byte[] SALT = "ProbeAesSalt2024".getBytes(StandardCharsets.UTF_8);
    
    private static final int MAX_CACHE_SIZE = 10;
    private static final int MAX_CIPHER_TEXT_LENGTH = 1024 * 1024;
    private static final ConcurrentHashMap<String, SecretKeySpec> keyCache = new ConcurrentHashMap<>();

    public static String encrypt(String plainText, String key) {
        try {
            SecretKeySpec secretKey = getSecretKey(key);

            byte[] iv = new byte[IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[IV_LENGTH + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, IV_LENGTH);
            System.arraycopy(encrypted, 0, combined, IV_LENGTH, encrypted.length);

            return Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            log.error("AES encryption error: {}", e.getMessage());
            return null;
        }
    }

    public static String decrypt(String cipherText, String key) {
        try {
            if (cipherText == null || cipherText.length() > MAX_CIPHER_TEXT_LENGTH) {
                return null;
            }
            byte[] combined = Base64.getDecoder().decode(cipherText);
            if (combined.length <= IV_LENGTH) {
                return null;
            }
            
            byte[] iv = new byte[IV_LENGTH];
            byte[] encrypted = new byte[combined.length - IV_LENGTH];
            System.arraycopy(combined, 0, iv, 0, IV_LENGTH);
            System.arraycopy(combined, IV_LENGTH, encrypted, 0, encrypted.length);

            SecretKeySpec secretKey = getSecretKey(key);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.error("AES decryption error: {}", e.getMessage());
            return null;
        }
    }

    private static SecretKeySpec getSecretKey(String key) {
        if (keyCache.size() >= MAX_CACHE_SIZE && !keyCache.containsKey(key)) {
            keyCache.clear();
        }
        return keyCache.computeIfAbsent(key, k -> {
            try {
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                KeySpec spec = new PBEKeySpec(k.toCharArray(), SALT, ITERATION_COUNT, KEY_LENGTH);
                byte[] keyBytes = factory.generateSecret(spec).getEncoded();
                return new SecretKeySpec(keyBytes, ALGORITHM);
            } catch (Exception e) {
                log.error("Key derivation error: {}", e.getMessage());
                byte[] fallbackKey = new byte[32];
                byte[] inputBytes = k.getBytes(StandardCharsets.UTF_8);
                System.arraycopy(inputBytes, 0, fallbackKey, 0, Math.min(inputBytes.length, 32));
                return new SecretKeySpec(fallbackKey, ALGORITHM);
            }
        });
    }
}
