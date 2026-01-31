package com.sports.gateway.probe.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("AES加解密工具测试")
class AesUtilTest {

    private static final String TEST_KEY = "test-aes-key-123";

    @Test
    @DisplayName("加密解密 - 正常流程")
    void encryptDecrypt_success() {
        String plainText = "{\"deviceId\":\"test-device-001\",\"appVersion\":\"1.0.0\"}";
        
        String encrypted = AesUtil.encrypt(plainText, TEST_KEY);
        assertNotNull(encrypted);
        assertNotEquals(plainText, encrypted);
        
        String decrypted = AesUtil.decrypt(encrypted, TEST_KEY);
        assertEquals(plainText, decrypted);
    }

    @Test
    @DisplayName("加密解密 - 中文内容")
    void encryptDecrypt_chinese() {
        String plainText = "{\"name\":\"测试设备\",\"carrier\":\"中国移动\"}";
        
        String encrypted = AesUtil.encrypt(plainText, TEST_KEY);
        String decrypted = AesUtil.decrypt(encrypted, TEST_KEY);
        
        assertEquals(plainText, decrypted);
    }

    @Test
    @DisplayName("加密解密 - 空字符串")
    void encryptDecrypt_emptyString() {
        String plainText = "";
        
        String encrypted = AesUtil.encrypt(plainText, TEST_KEY);
        assertNotNull(encrypted);
        
        String decrypted = AesUtil.decrypt(encrypted, TEST_KEY);
        assertEquals(plainText, decrypted);
    }

    @Test
    @DisplayName("加密解密 - 长文本")
    void encryptDecrypt_longText() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            sb.append("test-data-").append(i).append(",");
        }
        String plainText = sb.toString();
        
        String encrypted = AesUtil.encrypt(plainText, TEST_KEY);
        String decrypted = AesUtil.decrypt(encrypted, TEST_KEY);
        
        assertEquals(plainText, decrypted);
    }

    @Test
    @DisplayName("解密 - 错误密钥返回null")
    void decrypt_wrongKey_returnsNull() {
        String plainText = "test data";
        String encrypted = AesUtil.encrypt(plainText, TEST_KEY);
        
        String decrypted = AesUtil.decrypt(encrypted, "wrong-key-12345");
        
        assertNull(decrypted);
    }

    @Test
    @DisplayName("解密 - 非法Base64返回null")
    void decrypt_invalidBase64_returnsNull() {
        String result = AesUtil.decrypt("not-valid-base64!!!", TEST_KEY);
        assertNull(result);
    }

    @Test
    @DisplayName("解密 - 数据被篡改返回null")
    void decrypt_tamperedData_returnsNull() {
        String plainText = "test data";
        String encrypted = AesUtil.encrypt(plainText, TEST_KEY);
        
        String tampered = encrypted.substring(0, encrypted.length() - 5) + "XXXXX";
        String result = AesUtil.decrypt(tampered, TEST_KEY);
        
        assertNull(result);
    }

    @Test
    @DisplayName("解密 - null输入返回null")
    void decrypt_nullInput_returnsNull() {
        String result = AesUtil.decrypt(null, TEST_KEY);
        assertNull(result);
    }

    @Test
    @DisplayName("解密 - 数据太短返回null")
    void decrypt_tooShortData_returnsNull() {
        String shortData = java.util.Base64.getEncoder().encodeToString(new byte[10]);
        String result = AesUtil.decrypt(shortData, TEST_KEY);
        assertNull(result);
    }

    @Test
    @DisplayName("加密 - 每次IV不同，密文不同")
    void encrypt_differentIV_differentCiphertext() {
        String plainText = "same plain text";
        
        String encrypted1 = AesUtil.encrypt(plainText, TEST_KEY);
        String encrypted2 = AesUtil.encrypt(plainText, TEST_KEY);
        
        assertNotEquals(encrypted1, encrypted2);
        
        assertEquals(plainText, AesUtil.decrypt(encrypted1, TEST_KEY));
        assertEquals(plainText, AesUtil.decrypt(encrypted2, TEST_KEY));
    }

    @Test
    @DisplayName("密钥派生 - 短密钥可用")
    void encrypt_shortKey_works() {
        String plainText = "test data";
        String shortKey = "abc";
        
        String encrypted = AesUtil.encrypt(plainText, shortKey);
        String decrypted = AesUtil.decrypt(encrypted, shortKey);
        
        assertEquals(plainText, decrypted);
    }

    @Test
    @DisplayName("密钥派生 - 长密钥可用")
    void encrypt_longKey_works() {
        String plainText = "test data";
        String longKey = "this-is-a-very-long-key-that-exceeds-normal-length-requirements";
        
        String encrypted = AesUtil.encrypt(plainText, longKey);
        String decrypted = AesUtil.decrypt(encrypted, longKey);
        
        assertEquals(plainText, decrypted);
    }
}
