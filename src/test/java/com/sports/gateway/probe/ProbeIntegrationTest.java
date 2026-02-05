package com.sports.gateway.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sports.gateway.probe.dto.TokenRequest;
import com.sports.gateway.probe.dto.TokenResponse;
import com.sports.gateway.probe.util.AesUtil;
import com.sports.gateway.probe.util.HmacUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 探针功能集成测试示例
 * 
 * 此类演示如何模拟APP端的完整请求流程
 * 实际集成测试需要启动完整服务并连接Redis
 */
@DisplayName("探针功能集成测试示例")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ProbeIntegrationTest {

    private static final String AES_KEY = "test-aes-key-123";
    private static final String HMAC_SECRET = "test-hmac-secret";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    private static String savedToken;

    @Test
    @Order(1)
    @DisplayName("Step 1: 构造Token请求报文")
    void step1_buildTokenRequest() throws Exception {
        // 1. 构造明文请求
        TokenRequest request = new TokenRequest();
        request.setDeviceId("test-device-" + UUID.randomUUID().toString().substring(0, 8));
        request.setAppVersion("1.0.0");
        request.setTs(System.currentTimeMillis());

        String plainJson = objectMapper.writeValueAsString(request);
        System.out.println("明文请求: " + plainJson);

        // 2. AES加密
        String encryptedBody = AesUtil.encrypt(plainJson, AES_KEY);
        assertNotNull(encryptedBody);
        System.out.println("加密后Body: " + encryptedBody);

        // 3. 模拟服务端响应
        TokenResponse response = new TokenResponse();
        response.setToken(UUID.randomUUID().toString().replace("-", ""));
        response.setExpiresIn(1800L);
        
        String responseJson = objectMapper.writeValueAsString(response);
        String encryptedResponse = AesUtil.encrypt(responseJson, AES_KEY);
        System.out.println("加密后响应: " + encryptedResponse);

        // 4. 解密响应
        String decryptedResponse = AesUtil.decrypt(encryptedResponse, AES_KEY);
        TokenResponse parsedResponse = objectMapper.readValue(decryptedResponse, TokenResponse.class);
        
        assertNotNull(parsedResponse.getToken());
        assertEquals(1800L, parsedResponse.getExpiresIn());
        
        savedToken = parsedResponse.getToken();
        System.out.println("获取到Token: " + savedToken);
    }

    @Test
    @Order(2)
    @DisplayName("Step 2: 构造上报请求报文")
    void step2_buildUploadRequest() {
        String token = savedToken != null ? savedToken : "test-token-placeholder";
        
        // 1. 构造探针数据(AES加密)
        String probeData = """
            {
                "deviceId": "test-device-001",
                "platform": "ios",
                "appVersion": "1.0.0",
                "networkType": "wifi",
                "timestamp": %d,
                "probeResults": [
                    {
                        "domain": "api.example.com",
                        "dnsServer": "8.8.8.8",
                        "resolvedIp": "1.2.3.4",
                        "dnsLatency": 50,
                        "tcpLatency": 100,
                        "httpLatency": 200,
                        "httpStatusCode": 200
                    }
                ]
            }
            """.formatted(System.currentTimeMillis());

        String encryptedBody = AesUtil.encrypt(probeData, AES_KEY);
        byte[] bodyBytes = encryptedBody.getBytes();
        
        // 2. 构造签名Headers
        String ts = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        String bodyHash = HmacUtil.sha256Hash(bodyBytes);
        String sign = HmacUtil.generateHmac(ts, nonce, bodyHash, HMAC_SECRET);

        System.out.println("=== 上报请求构造 ===");
        System.out.println("X-Probe-Token: " + token);
        System.out.println("X-Ts: " + ts);
        System.out.println("X-Nonce: " + nonce);
        System.out.println("X-Sign: " + sign);
        System.out.println("Body: " + encryptedBody.substring(0, Math.min(50, encryptedBody.length())) + "...");

        // 3. 验证签名
        boolean valid = HmacUtil.validateHmac(ts, nonce, bodyHash, sign, HMAC_SECRET);
        assertTrue(valid, "签名验证应该通过");
    }

    @Test
    @Order(3)
    @DisplayName("Step 3: 验证时间戳校验逻辑")
    void step3_timestampValidation() {
        long now = System.currentTimeMillis();
        long fiveMinutesAgo = now - (5 * 60 * 1000);
        long tenMinutesAgo = now - (10 * 60 * 1000);
        long fiveMinutesLater = now + (5 * 60 * 1000);

        // 当前时间 - 有效
        assertTrue(isTimestampValid(now, 5), "当前时间戳应该有效");
        
        // 5分钟前 - 边界有效
        assertTrue(isTimestampValid(fiveMinutesAgo, 5), "5分钟前的时间戳应该有效");
        
        // 10分钟前 - 无效
        assertFalse(isTimestampValid(tenMinutesAgo, 5), "10分钟前的时间戳应该无效");
        
        // 5分钟后 - 边界有效(允许时钟偏差)
        assertTrue(isTimestampValid(fiveMinutesLater, 5), "5分钟后的时间戳应该有效");
    }

    @Test
    @Order(4)
    @DisplayName("Step 4: 验证Nonce唯一性要求")
    void step4_nonceUniqueness() {
        String nonce1 = UUID.randomUUID().toString().replace("-", "");
        String nonce2 = UUID.randomUUID().toString().replace("-", "");
        
        assertNotEquals(nonce1, nonce2, "每次请求的Nonce应该不同");
        assertEquals(32, nonce1.length(), "Nonce长度应该是32字符");
        assertTrue(nonce1.matches("[a-f0-9]+"), "Nonce应该是十六进制字符");
    }

    @Test
    @Order(5)
    @DisplayName("Step 5: 验证HMAC防篡改")
    void step5_hmacTamperProtection() {
        String ts = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        String bodyHash = HmacUtil.sha256Hash("test body".getBytes());
        
        String sign = HmacUtil.generateHmac(ts, nonce, bodyHash, HMAC_SECRET);
        
        // 正常验证 - 通过
        assertTrue(HmacUtil.validateHmac(ts, nonce, bodyHash, sign, HMAC_SECRET));
        
        // 时间戳被篡改 - 失败
        assertFalse(HmacUtil.validateHmac(ts + "1", nonce, bodyHash, sign, HMAC_SECRET));
        
        // Nonce被篡改 - 失败
        assertFalse(HmacUtil.validateHmac(ts, nonce + "x", bodyHash, sign, HMAC_SECRET));
        
        // Body被篡改 - 失败
        String tamperedBodyHash = HmacUtil.sha256Hash("tampered body".getBytes());
        assertFalse(HmacUtil.validateHmac(ts, nonce, tamperedBodyHash, sign, HMAC_SECRET));
    }

    private boolean isTimestampValid(long timestamp, int validMinutes) {
        long now = System.currentTimeMillis();
        long diff = Math.abs(now - timestamp);
        long maxDiff = validMinutes * 60 * 1000L;
        return diff <= maxDiff;
    }
}
