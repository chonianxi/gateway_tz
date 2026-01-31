package com.sports.gateway.probe.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("HMAC签名工具测试")
class HmacUtilTest {

    private static final String TEST_SECRET = "test-hmac-secret";

    @Test
    @DisplayName("生成HMAC - 正常流程")
    void generateHmac_success() {
        String ts = "1706598000000";
        String nonce = "abc123def456";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        String hmac = HmacUtil.generateHmac(ts, nonce, bodyHash, TEST_SECRET);
        
        assertNotNull(hmac);
        assertEquals(64, hmac.length());
    }

    @Test
    @DisplayName("验证HMAC - 正确签名")
    void validateHmac_correctSignature() {
        String ts = "1706598000000";
        String nonce = "abc123def456";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        String hmac = HmacUtil.generateHmac(ts, nonce, bodyHash, TEST_SECRET);
        
        boolean valid = HmacUtil.validateHmac(ts, nonce, bodyHash, hmac, TEST_SECRET);
        assertTrue(valid);
    }

    @Test
    @DisplayName("验证HMAC - 错误签名")
    void validateHmac_wrongSignature() {
        String ts = "1706598000000";
        String nonce = "abc123def456";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        boolean valid = HmacUtil.validateHmac(ts, nonce, bodyHash, "wrong-signature", TEST_SECRET);
        assertFalse(valid);
    }

    @Test
    @DisplayName("验证HMAC - 时间戳被篡改")
    void validateHmac_tamperedTs() {
        String ts = "1706598000000";
        String nonce = "abc123def456";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        String hmac = HmacUtil.generateHmac(ts, nonce, bodyHash, TEST_SECRET);
        
        boolean valid = HmacUtil.validateHmac("1706598000001", nonce, bodyHash, hmac, TEST_SECRET);
        assertFalse(valid);
    }

    @Test
    @DisplayName("验证HMAC - Nonce被篡改")
    void validateHmac_tamperedNonce() {
        String ts = "1706598000000";
        String nonce = "abc123def456";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        String hmac = HmacUtil.generateHmac(ts, nonce, bodyHash, TEST_SECRET);
        
        boolean valid = HmacUtil.validateHmac(ts, "different-nonce", bodyHash, hmac, TEST_SECRET);
        assertFalse(valid);
    }

    @Test
    @DisplayName("验证HMAC - Body被篡改")
    void validateHmac_tamperedBody() {
        String ts = "1706598000000";
        String nonce = "abc123def456";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        String hmac = HmacUtil.generateHmac(ts, nonce, bodyHash, TEST_SECRET);
        
        boolean valid = HmacUtil.validateHmac(ts, nonce, "different-body-hash", hmac, TEST_SECRET);
        assertFalse(valid);
    }

    @Test
    @DisplayName("验证HMAC - 错误密钥")
    void validateHmac_wrongSecret() {
        String ts = "1706598000000";
        String nonce = "abc123def456";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        
        String hmac = HmacUtil.generateHmac(ts, nonce, bodyHash, TEST_SECRET);
        
        boolean valid = HmacUtil.validateHmac(ts, nonce, bodyHash, hmac, "wrong-secret");
        assertFalse(valid);
    }

    @Test
    @DisplayName("SHA256哈希 - 正常数据")
    void sha256Hash_normalData() {
        byte[] data = "test data".getBytes();
        
        String hash = HmacUtil.sha256Hash(data);
        
        assertNotNull(hash);
        assertEquals(64, hash.length());
    }

    @Test
    @DisplayName("SHA256哈希 - 空数据")
    void sha256Hash_emptyData() {
        byte[] data = new byte[0];
        
        String hash = HmacUtil.sha256Hash(data);
        
        assertNotNull(hash);
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    @Test
    @DisplayName("SHA256哈希 - 相同数据产生相同哈希")
    void sha256Hash_deterministic() {
        byte[] data = "test data".getBytes();
        
        String hash1 = HmacUtil.sha256Hash(data);
        String hash2 = HmacUtil.sha256Hash(data);
        
        assertEquals(hash1, hash2);
    }

    @Test
    @DisplayName("HMAC签名 - 防止时序攻击")
    void validateHmac_timingSafe() {
        String ts = "1706598000000";
        String nonce = "abc123def456";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        String hmac = HmacUtil.generateHmac(ts, nonce, bodyHash, TEST_SECRET);
        
        String almostCorrect = hmac.substring(0, hmac.length() - 1) + "X";
        String totallyWrong = "0000000000000000000000000000000000000000000000000000000000000000";
        
        boolean valid1 = HmacUtil.validateHmac(ts, nonce, bodyHash, almostCorrect, TEST_SECRET);
        boolean valid2 = HmacUtil.validateHmac(ts, nonce, bodyHash, totallyWrong, TEST_SECRET);
        
        assertFalse(valid1);
        assertFalse(valid2);
    }
}
