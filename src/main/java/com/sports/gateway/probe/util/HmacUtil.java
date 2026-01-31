package com.sports.gateway.probe.util;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Slf4j
public class HmacUtil {

    private static final String HMAC_SHA256 = "HmacSHA256";

    public static String generateHmac(String ts, String nonce, String bodyHash, String secret) {
        try {
            String input = ts + nonce + bodyHash;
            
            Mac mac = Mac.getInstance(HMAC_SHA256);
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256);
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
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (Exception e) {
            log.error("SHA256 hash error: {}", e.getMessage());
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
