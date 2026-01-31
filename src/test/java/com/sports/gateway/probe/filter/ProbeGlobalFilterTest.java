package com.sports.gateway.probe.filter;

import com.alibaba.fastjson.JSON;
import com.sports.gateway.config.properties.ProbeProperties;
import com.sports.gateway.probe.dto.TokenRequest;
import com.sports.gateway.probe.service.NonceService;
import com.sports.gateway.probe.service.ProbeIpRateLimitService;
import com.sports.gateway.probe.service.ProbeTokenService;
import com.sports.gateway.probe.util.AesUtil;
import com.sports.gateway.probe.util.HmacUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.net.InetSocketAddress;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("探针全局过滤器测试")
class ProbeGlobalFilterTest {

    @Mock
    private ProbeIpRateLimitService rateLimitService;
    
    @Mock
    private ProbeTokenService tokenService;
    
    @Mock
    private NonceService nonceService;
    
    @Mock
    private GatewayFilterChain chain;

    private ProbeProperties probeProperties;
    private ProbeGlobalFilter filter;

    private static final String AES_KEY = "test-aes-key-123";
    private static final String HMAC_SECRET = "test-hmac-secret";

    @BeforeEach
    void setUp() {
        probeProperties = new ProbeProperties();
        probeProperties.setEnabled(true);
        probeProperties.setTokenEnabled(true);
        probeProperties.setDnsConfigEnabled(true);
        probeProperties.setUploadEnabled(true);
        probeProperties.setAesKey(AES_KEY);
        probeProperties.setHmacSecret(HMAC_SECRET);
        probeProperties.setTimestampValidMinutes(5);
        
        ProbeProperties.Paths paths = new ProbeProperties.Paths();
        probeProperties.setPaths(paths);

        probeProperties.setProbeDnsServers(java.util.Arrays.asList("8.8.8.8", "114.114.114.114"));
        
        ProbeProperties.DomainCategory apiCategory = new ProbeProperties.DomainCategory();
        apiCategory.setName("API");
        apiCategory.setDescription("API servers");
        apiCategory.setDomains(java.util.Arrays.asList("api.example.com"));
        probeProperties.getDomainCategories().put("api", apiCategory);

        filter = new ProbeGlobalFilter(probeProperties, rateLimitService, tokenService, nonceService);
    }

    @Nested
    @DisplayName("Token接口测试")
    class TokenEndpointTests {

        @Test
        @DisplayName("功能关闭时返回410")
        void tokenDisabled_returns410() {
            probeProperties.setTokenEnabled(false);
            
            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/token")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.GONE;
        }

        @Test
        @DisplayName("IP限流触发返回204")
        void rateLimited_returns204() {
            when(rateLimitService.allowProbeRequest(anyString(), anyString()))
                    .thenReturn(Mono.just(false));

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/token")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.NO_CONTENT;
        }

        @Test
        @DisplayName("解密失败返回204")
        void decryptionFailed_returns204() {
            when(rateLimitService.allowProbeRequest(anyString(), anyString()))
                    .thenReturn(Mono.just(true));

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/token")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .body("invalid-encrypted-data");
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.NO_CONTENT;
        }
    }

    @Nested
    @DisplayName("上传接口Header校验测试")
    class UploadHeaderValidationTests {

        @Test
        @DisplayName("缺少必需Header返回204")
        void missingHeaders_returns204() {
            when(rateLimitService.allowProbeRequest(anyString(), anyString()))
                    .thenReturn(Mono.just(true));

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/upload")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.NO_CONTENT;
        }

        @Test
        @DisplayName("Nonce过长返回204")
        void nonceTooLong_returns204() {
            when(rateLimitService.allowProbeRequest(anyString(), anyString()))
                    .thenReturn(Mono.just(true));

            String longNonce = "a".repeat(100);
            
            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/upload")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .header("X-Ts", String.valueOf(System.currentTimeMillis()))
                    .header("X-Nonce", longNonce)
                    .header("X-Sign", "test-sign")
                    .header("X-Probe-Token", "test-token")
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.NO_CONTENT;
        }

        @Test
        @DisplayName("时间戳过期返回204")
        void timestampExpired_returns204() {
            when(rateLimitService.allowProbeRequest(anyString(), anyString()))
                    .thenReturn(Mono.just(true));

            long expiredTs = System.currentTimeMillis() - (10 * 60 * 1000);
            
            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/upload")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .header("X-Ts", String.valueOf(expiredTs))
                    .header("X-Nonce", "test-nonce-123")
                    .header("X-Sign", "test-sign")
                    .header("X-Probe-Token", "test-token")
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.NO_CONTENT;
        }

        @Test
        @DisplayName("时间戳格式错误返回204")
        void invalidTimestamp_returns204() {
            when(rateLimitService.allowProbeRequest(anyString(), anyString()))
                    .thenReturn(Mono.just(true));

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/upload")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .header("X-Ts", "not-a-number")
                    .header("X-Nonce", "test-nonce-123")
                    .header("X-Sign", "test-sign")
                    .header("X-Probe-Token", "test-token")
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.NO_CONTENT;
        }
    }

    @Nested
    @DisplayName("功能开关测试")
    class FeatureSwitchTests {

        @Test
        @DisplayName("总开关关闭时透传请求")
        void probeDisabled_passThrough() {
            probeProperties.setEnabled(false);
            when(chain.filter(any())).thenReturn(Mono.empty());

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/token")
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();
        }

        @Test
        @DisplayName("DNS配置关闭返回410")
        void dnsConfigDisabled_returns410() {
            probeProperties.setDnsConfigEnabled(false);

            MockServerHttpRequest request = MockServerHttpRequest
                    .get("/api/probe/ios/dns-config")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.GONE;
        }

        @Test
        @DisplayName("上传关闭返回410")
        void uploadDisabled_returns410() {
            probeProperties.setUploadEnabled(false);

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/android/upload")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            StepVerifier.create(filter.filter(exchange, chain))
                    .verifyComplete();

            assert exchange.getResponse().getStatusCode() == HttpStatus.GONE;
        }
    }

    @Nested
    @DisplayName("IP获取测试")
    class IpExtractionTests {

        @Test
        @DisplayName("从X-Real-IP获取")
        void extractFromXRealIP() {
            when(rateLimitService.allowProbeRequest("10.0.0.1", "token"))
                    .thenReturn(Mono.just(false));

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/token")
                    .header("X-Real-IP", "10.0.0.1")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            filter.filter(exchange, chain).block();
        }

        @Test
        @DisplayName("从X-Forwarded-For获取第一个IP")
        void extractFromXForwardedFor() {
            when(rateLimitService.allowProbeRequest("10.0.0.2", "token"))
                    .thenReturn(Mono.just(false));

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/token")
                    .header("X-Forwarded-For", "10.0.0.2, 10.0.0.3, 10.0.0.4")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            filter.filter(exchange, chain).block();
        }

        @Test
        @DisplayName("无效IP格式使用remoteAddress")
        void invalidIpFormat_fallbackToRemote() {
            when(rateLimitService.allowProbeRequest("192.168.1.1", "token"))
                    .thenReturn(Mono.just(false));

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/token")
                    .header("X-Real-IP", "invalid<script>ip")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            filter.filter(exchange, chain).block();
        }
    }

    @Nested
    @DisplayName("平台识别测试")
    class PlatformDetectionTests {

        @Test
        @DisplayName("iOS路径识别")
        void detectIosPlatform() {
            probeProperties.setTokenEnabled(false);

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/ios/token")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            filter.filter(exchange, chain).block();

            assert exchange.getResponse().getStatusCode() == HttpStatus.GONE;
        }

        @Test
        @DisplayName("Android路径识别")
        void detectAndroidPlatform() {
            probeProperties.setTokenEnabled(false);

            MockServerHttpRequest request = MockServerHttpRequest
                    .post("/api/probe/android/token")
                    .remoteAddress(new InetSocketAddress("192.168.1.1", 8080))
                    .build();
            MockServerWebExchange exchange = MockServerWebExchange.from(request);

            filter.filter(exchange, chain).block();

            assert exchange.getResponse().getStatusCode() == HttpStatus.GONE;
        }
    }
}
