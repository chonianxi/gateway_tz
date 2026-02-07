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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 探针功能集成测试示例
 * 
 * 此类演示如何模拟APP端的完整请求流程
 * 实际集成测试需要启动完整服务并连接Redis
 * 
 * === 加密参数说明 (客户端实现必读) ===
 * 
 * AES加密配置:
 *   - 算法: AES/CBC/PKCS5Padding
 *   - 密钥长度: 256位
 *   - IV长度: 16字节 (随机生成)
 *   - 密文格式: Base64(IV + EncryptedData)
 *   - 密钥派生: PBKDF2WithHmacSHA256
 *   - 迭代次数: 4096
 *   - SALT: "ProbeAesSalt2024" (UTF-8编码)
 * 
 * HMAC签名配置:
 *   - 算法: HmacSHA256
 *   - 签名内容: ts + nonce + SHA256(body)
 *   - 输出格式: 小写十六进制字符串
 */
@DisplayName("探针功能集成测试示例")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ProbeIntegrationTest {

    // 商户配置 (对应application.yml中的apps配置)
    private static final String APP_ID = "app001";
    private static final String AES_KEY = "test-aes-key-123";
    private static final String HMAC_SECRET = "test-hmac-secret";
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    // AES加密参数 (客户端实现需要)
    private static final int IV_LENGTH = 16;
    private static final String PBKDF2_SALT = "ProbeAesSalt2024";
    private static final int PBKDF2_ITERATIONS = 4096;
    private static final int AES_KEY_LENGTH = 256;
    
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

        // 2. AES加密 (使用商户的AES密钥)
        String encryptedBody = AesUtil.encrypt(plainJson, AES_KEY);
        assertNotNull(encryptedBody);
        System.out.println("加密后Body: " + encryptedBody);
        System.out.println("X-App-Id: " + APP_ID);

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
        
        // 输出TOKEN请求的curl命令
        System.out.println("\ncurl命令:");
        System.out.printf("curl -X POST 'http://localhost:8080/api/probe/ios/token' \\%n");
        System.out.printf("  -H 'Content-Type: application/json' \\%n");
        System.out.printf("  -H 'X-App-Id: %s' \\%n", APP_ID);
        System.out.printf("  -d '%s'%n", encryptedBody);
    }

    @Test
    @Order(2)
    @DisplayName("Step 2: 构造上报请求报文")
    void step2_buildUploadRequest() {
        String token = savedToken != null ? savedToken : "test-token-placeholder";
        
        // 1. 构造探针数据(AES加密, 使用商户的AES密钥)
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
        System.out.println("X-App-Id: " + APP_ID);
        System.out.println("X-Probe-Token: " + token);
        System.out.println("X-Ts: " + ts);
        System.out.println("X-Nonce: " + nonce);
        System.out.println("X-Sign: " + sign);
        System.out.println("Body: " + encryptedBody.substring(0, Math.min(50, encryptedBody.length())) + "...");
        
        // 输出curl命令
        System.out.println("\ncurl命令:");
        System.out.printf("curl -X POST 'http://localhost:8080/api/probe/ios/upload' \\%n");
        System.out.printf("  -H 'Content-Type: application/json' \\%n");
        System.out.printf("  -H 'X-App-Id: %s' \\%n", APP_ID);
        System.out.printf("  -H 'X-Probe-Token: %s' \\%n", token);
        System.out.printf("  -H 'X-Ts: %s' \\%n", ts);
        System.out.printf("  -H 'X-Nonce: %s' \\%n", nonce);
        System.out.printf("  -H 'X-Sign: %s' \\%n", sign);
        System.out.printf("  -d '%s'%n", encryptedBody);

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

    @Test
    @Order(6)
    @DisplayName("Step 6: 构造DNS配置请求报文")
    void step6_buildDnsConfigRequest() {
        String token = savedToken != null ? savedToken : "test-token-placeholder";
        
        System.out.println("=== DNS配置请求构造 ===");
        System.out.println("X-App-Id: " + APP_ID);
        System.out.println("X-Probe-Token: " + token);
        
        // 输出curl命令
        System.out.println("\ncurl命令:");
        System.out.printf("curl -X POST 'http://localhost:8080/api/probe/ios/dns-config' \\%n");
        System.out.printf("  -H 'Content-Type: application/json' \\%n");
        System.out.printf("  -H 'X-App-Id: %s' \\%n", APP_ID);
        System.out.printf("  -H 'X-Probe-Token: %s'%n", token);
        
        assertNotNull(token);
    }

    @Test
    @Order(7)
    @DisplayName("Step 7: 构造H5上报请求报文 (无需签名)")
    void step7_buildH5UploadRequest() {
        // H5请求不需要Token和签名，只需要appId
        String h5ProbeData = """
            {
                "deviceId": "h5-browser-001",
                "platform": "h5",
                "appVersion": "1.0.0",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "timestamp": %d,
                "probeResults": [
                    {
                        "domain": "api.example.com",
                        "dnsLatency": 30,
                        "tcpLatency": 80,
                        "httpLatency": 150,
                        "httpStatusCode": 200
                    }
                ]
            }
            """.formatted(System.currentTimeMillis());

        System.out.println("=== H5上报请求构造 ===");
        System.out.println("X-App-Id: " + APP_ID);
        System.out.println("Body (明文JSON): " + h5ProbeData.substring(0, Math.min(100, h5ProbeData.length())) + "...");
        
        // 输出curl命令
        System.out.println("\ncurl命令:");
        System.out.printf("curl -X POST 'http://localhost:8080/api/probe/h5/upload' \\%n");
        System.out.printf("  -H 'Content-Type: application/json' \\%n");
        System.out.printf("  -H 'X-App-Id: %s' \\%n", APP_ID);
        System.out.printf("  -d '%s'%n", h5ProbeData.replace("\n", "").replace(" ", ""));
        
        assertNotNull(h5ProbeData);
    }

    @Test
    @Order(8)
    @DisplayName("Step 8: 验证AES加密IV机制")
    void step8_verifyAesIvMechanism() {
        String plainText = "Hello, 探针!";
        
        // 加密两次，验证IV不同导致密文不同
        String encrypted1 = AesUtil.encrypt(plainText, AES_KEY);
        String encrypted2 = AesUtil.encrypt(plainText, AES_KEY);
        
        assertNotNull(encrypted1);
        assertNotNull(encrypted2);
        assertNotEquals(encrypted1, encrypted2, "相同明文加密两次应产生不同密文(因为IV随机)");
        
        // 验证密文结构: Base64(IV[16字节] + EncryptedData)
        byte[] decoded1 = Base64.getDecoder().decode(encrypted1);
        byte[] decoded2 = Base64.getDecoder().decode(encrypted2);
        
        assertTrue(decoded1.length > IV_LENGTH, "密文长度应大于IV长度");
        assertTrue(decoded2.length > IV_LENGTH, "密文长度应大于IV长度");
        
        // 提取IV (前16字节)
        byte[] iv1 = new byte[IV_LENGTH];
        byte[] iv2 = new byte[IV_LENGTH];
        System.arraycopy(decoded1, 0, iv1, 0, IV_LENGTH);
        System.arraycopy(decoded2, 0, iv2, 0, IV_LENGTH);
        
        assertFalse(java.util.Arrays.equals(iv1, iv2), "两次加密的IV应该不同");
        
        // 验证两个密文都能正确解密
        String decrypted1 = AesUtil.decrypt(encrypted1, AES_KEY);
        String decrypted2 = AesUtil.decrypt(encrypted2, AES_KEY);
        
        assertEquals(plainText, decrypted1, "解密结果应与原文相同");
        assertEquals(plainText, decrypted2, "解密结果应与原文相同");
        
        System.out.println("=== AES IV机制验证 ===");
        System.out.println("明文: " + plainText);
        System.out.println("密文1: " + encrypted1);
        System.out.println("密文2: " + encrypted2);
        System.out.println("IV1 (hex): " + bytesToHex(iv1));
        System.out.println("IV2 (hex): " + bytesToHex(iv2));
        System.out.println("解密1: " + decrypted1);
        System.out.println("解密2: " + decrypted2);
        
        // 输出客户端实现说明
        System.out.println("\n=== 客户端实现说明 ===");
        System.out.println("1. 加密时生成16字节随机IV");
        System.out.println("2. 使用AES/CBC/PKCS5Padding加密");
        System.out.println("3. 将IV拼接在密文前面: IV + EncryptedData");
        System.out.println("4. 整体进行Base64编码");
        System.out.println("5. 密钥派生: PBKDF2WithHmacSHA256");
        System.out.println("   - SALT: \"" + PBKDF2_SALT + "\"");
        System.out.println("   - 迭代次数: " + PBKDF2_ITERATIONS);
        System.out.println("   - 密钥长度: " + AES_KEY_LENGTH + "位");
    }

    @Test
    @Order(9)
    @DisplayName("Step 9: 验证PBKDF2密钥派生")
    void step9_verifyPbkdf2KeyDerivation() throws Exception {
        // 使用Java标准库验证PBKDF2派生
        javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                AES_KEY.toCharArray(),
                PBKDF2_SALT.getBytes(StandardCharsets.UTF_8),
                PBKDF2_ITERATIONS,
                AES_KEY_LENGTH
        );
        byte[] derivedKey = factory.generateSecret(spec).getEncoded();
        
        assertEquals(32, derivedKey.length, "派生密钥应为32字节(256位)");
        
        System.out.println("=== PBKDF2密钥派生验证 ===");
        System.out.println("原始密钥: " + AES_KEY);
        System.out.println("SALT: " + PBKDF2_SALT);
        System.out.println("迭代次数: " + PBKDF2_ITERATIONS);
        System.out.println("派生密钥 (hex): " + bytesToHex(derivedKey));
        System.out.println("派生密钥长度: " + derivedKey.length + "字节");
        
        // 客户端可以用这个派生密钥来验证自己的PBKDF2实现是否正确
        System.out.println("\n注意: 客户端实现时，使用相同参数应得到相同的派生密钥");
    }

    @Test
    @Order(10)
    @DisplayName("Step 10: 完整请求流程演示")
    void step10_completeRequestFlow() throws Exception {
        System.out.println("=== 完整请求流程演示 ===\n");
        
        // Step 1: 获取Token
        System.out.println("【第一步: 获取Token】");
        TokenRequest tokenReq = new TokenRequest();
        tokenReq.setDeviceId("device-" + UUID.randomUUID().toString().substring(0, 8));
        tokenReq.setAppVersion("2.0.0");
        tokenReq.setTs(System.currentTimeMillis());
        
        String tokenBody = AesUtil.encrypt(objectMapper.writeValueAsString(tokenReq), AES_KEY);
        System.out.println("POST /api/probe/ios/token");
        System.out.println("Headers: X-App-Id=" + APP_ID);
        System.out.println("Body: " + tokenBody.substring(0, 50) + "...");
        
        // 模拟获取到的Token
        String token = UUID.randomUUID().toString().replace("-", "");
        System.out.println("响应Token: " + token + "\n");
        
        // Step 2: 获取DNS配置
        System.out.println("【第二步: 获取DNS配置】");
        System.out.println("POST /api/probe/ios/dns-config");
        System.out.println("Headers: X-App-Id=" + APP_ID + ", X-Probe-Token=" + token);
        System.out.println("响应: 加密的DNS配置JSON\n");
        
        // Step 3: 上传探针数据
        System.out.println("【第三步: 上传探针数据】");
        String probeJson = "{\"deviceId\":\"device-001\",\"results\":[]}";
        String encryptedProbe = AesUtil.encrypt(probeJson, AES_KEY);
        byte[] probeBytes = encryptedProbe.getBytes(StandardCharsets.UTF_8);
        
        String ts = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        String bodyHash = HmacUtil.sha256Hash(probeBytes);
        String sign = HmacUtil.generateHmac(ts, nonce, bodyHash, HMAC_SECRET);
        
        System.out.println("POST /api/probe/ios/upload");
        System.out.println("Headers:");
        System.out.println("  X-App-Id: " + APP_ID);
        System.out.println("  X-Probe-Token: " + token);
        System.out.println("  X-Ts: " + ts);
        System.out.println("  X-Nonce: " + nonce);
        System.out.println("  X-Sign: " + sign);
        System.out.println("Body: " + encryptedProbe.substring(0, 50) + "...");
        System.out.println("响应: HTTP 200 OK\n");
        
        System.out.println("=== 流程完成 ===");
        
        assertNotNull(tokenBody);
        assertNotNull(sign);
    }

    private boolean isTimestampValid(long timestamp, int validMinutes) {
        long now = System.currentTimeMillis();
        long diff = Math.abs(now - timestamp);
        long maxDiff = validMinutes * 60 * 1000L;
        return diff <= maxDiff;
    }
    
    private String bytesToHex(byte[] bytes) {
        char[] hexChars = "0123456789abcdef".toCharArray();
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(hexChars[(b >> 4) & 0x0F]);
            sb.append(hexChars[b & 0x0F]);
        }
        return sb.toString();
    }
}
