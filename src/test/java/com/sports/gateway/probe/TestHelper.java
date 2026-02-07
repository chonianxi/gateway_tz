package com.sports.gateway.probe;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sports.gateway.probe.dto.TokenRequest;
import com.sports.gateway.probe.util.AesUtil;
import com.sports.gateway.probe.util.HmacUtil;

import java.util.UUID;

/**
 * 测试辅助工具类
 * 
 * 用于生成测试用的加密请求和签名
 * 可以通过main方法运行，生成curl测试所需的数据
 */
public class TestHelper {

    // 商户配置 (对应application.yml中的apps配置)
    private static final String APP_ID = "app001";
    private static final String AES_KEY = "test-aes-key-123";
    private static final String HMAC_SECRET = "test-hmac-secret";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static void main(String[] args) {
        System.out.println("=== 探针API测试数据生成器 ===\n");

        // 1. 生成Token请求
        generateTokenRequest();

        // 2. 生成上传请求
        generateUploadRequest("your-token-here");
    }

    /**
     * 生成Token请求的加密Body
     */
    public static void generateTokenRequest() {
        System.out.println("=== Token请求 ===");
        
        try {
            TokenRequest request = new TokenRequest();
            request.setDeviceId("device-" + UUID.randomUUID().toString().substring(0, 8));
            request.setAppVersion("1.0.0");
            request.setTs(System.currentTimeMillis());

            String plainJson = objectMapper.writeValueAsString(request);
        System.out.println("明文: " + plainJson);

        String encrypted = AesUtil.encrypt(plainJson, AES_KEY);
        System.out.println("加密Body: " + encrypted);
        
        System.out.println("\ncurl命令:");
        System.out.printf("curl -X POST 'http://localhost:8080/api/probe/ios/token' \\%n");
        System.out.printf("  -H 'Content-Type: application/json' \\%n");
        System.out.printf("  -H 'X-App-Id: %s' \\%n", APP_ID);
        System.out.printf("  -d '%s'%n", encrypted);
        System.out.println();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成上传请求的Headers和Body
     */
    public static void generateUploadRequest(String token) {
        System.out.println("=== 上传请求 ===");
        
        // 构造探针数据
        String probeData = """
            {
                "deviceId": "device-001",
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

        // 生成签名
        String ts = String.valueOf(System.currentTimeMillis());
        String nonce = UUID.randomUUID().toString().replace("-", "");
        String bodyHash = HmacUtil.sha256Hash(bodyBytes);
        String sign = HmacUtil.generateHmac(ts, nonce, bodyHash, HMAC_SECRET);

        System.out.println("X-App-Id: " + APP_ID);
        System.out.println("X-Probe-Token: " + token);
        System.out.println("X-Ts: " + ts);
        System.out.println("X-Nonce: " + nonce);
        System.out.println("X-Sign: " + sign);
        System.out.println("Body: " + encryptedBody.substring(0, 50) + "...");
        
        System.out.println("\ncurl命令:");
        System.out.printf("curl -X POST 'http://localhost:8080/api/probe/ios/upload' \\%n");
        System.out.printf("  -H 'Content-Type: application/json' \\%n");
        System.out.printf("  -H 'X-App-Id: %s' \\%n", APP_ID);
        System.out.printf("  -H 'X-Probe-Token: %s' \\%n", token);
        System.out.printf("  -H 'X-Ts: %s' \\%n", ts);
        System.out.printf("  -H 'X-Nonce: %s' \\%n", nonce);
        System.out.printf("  -H 'X-Sign: %s' \\%n", sign);
        System.out.printf("  -d '%s'%n", encryptedBody);
        System.out.println();
    }

    /**
     * 生成DNS配置请求
     */
    public static void generateDnsConfigRequest(String token) {
        System.out.println("=== DNS配置请求 ===");
        
        System.out.println("X-App-Id: " + APP_ID);
        System.out.println("X-Probe-Token: " + token);
        
        System.out.println("\ncurl命令:");
        System.out.printf("curl -X POST 'http://localhost:8080/api/probe/ios/dns-config' \\%n");
        System.out.printf("  -H 'Content-Type: application/json' \\%n");
        System.out.printf("  -H 'X-App-Id: %s' \\%n", APP_ID);
        System.out.printf("  -H 'X-Probe-Token: %s'%n", token);
        System.out.println();
    }

    /**
     * 生成H5上报请求 (无需Token和签名)
     */
    public static void generateH5UploadRequest() {
        System.out.println("=== H5上报请求 ===");
        
        String h5ProbeData = """
            {
                "deviceId": "h5-browser-001",
                "platform": "h5",
                "appVersion": "1.0.0",
                "userAgent": "Mozilla/5.0",
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

        System.out.println("X-App-Id: " + APP_ID);
        System.out.println("Body: " + h5ProbeData.substring(0, 50) + "...");
        
        System.out.println("\ncurl命令:");
        System.out.printf("curl -X POST 'http://localhost:8080/api/probe/h5/upload' \\%n");
        System.out.printf("  -H 'Content-Type: application/json' \\%n");
        System.out.printf("  -H 'X-App-Id: %s' \\%n", APP_ID);
        System.out.printf("  -d '%s'%n", h5ProbeData.replace("\n", "").replace(" ", ""));
        System.out.println();
    }

    /**
     * 解密响应
     */
    public static String decryptResponse(String encryptedResponse) {
        return AesUtil.decrypt(encryptedResponse, AES_KEY);
    }

    /**
     * 验证HMAC签名
     */
    public static boolean verifySign(String ts, String nonce, byte[] body, String sign) {
        String bodyHash = HmacUtil.sha256Hash(body);
        return HmacUtil.validateHmac(ts, nonce, bodyHash, sign, HMAC_SECRET);
    }
}
