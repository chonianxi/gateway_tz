package com.sports.gateway.probe.filter;

import cn.hutool.core.util.StrUtil;
import com.alibaba.fastjson.JSON;
import com.sports.gateway.config.properties.ProbeProperties;
import com.sports.gateway.probe.dto.DnsConfigResponse;
import com.sports.gateway.probe.dto.TokenRequest;
import com.sports.gateway.probe.dto.TokenResponse;
import com.sports.gateway.probe.service.NonceService;
import com.sports.gateway.probe.service.ProbeIpRateLimitService;
import com.sports.gateway.probe.service.ProbeTokenService;
import com.sports.gateway.probe.util.AesUtil;
import com.sports.gateway.probe.util.HmacUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

@Slf4j
@Component
public class ProbeGlobalFilter implements GlobalFilter, Ordered {

    private static final String HEADER_X_TS = "X-Ts";
    private static final String HEADER_X_NONCE = "X-Nonce";
    private static final String HEADER_X_SIGN = "X-Sign";
    private static final String HEADER_X_TOKEN = "X-Probe-Token";

    private static final int MAX_BODY_SIZE = 64 * 1024;
    private static final int MAX_NONCE_LENGTH = 64;
    private static final int MAX_TOKEN_LENGTH = 64;
    private static final int MAX_SIGN_LENGTH = 128;
    private static final int MAX_TS_LENGTH = 16;

    private final ProbeProperties probeProperties;
    private final ProbeIpRateLimitService rateLimitService;
    private final ProbeTokenService tokenService;
    private final NonceService nonceService;

    public ProbeGlobalFilter(ProbeProperties probeProperties,
                             ProbeIpRateLimitService rateLimitService,
                             ProbeTokenService tokenService,
                             NonceService nonceService) {
        this.probeProperties = probeProperties;
        this.rateLimitService = rateLimitService;
        this.tokenService = tokenService;
        this.nonceService = nonceService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!probeProperties.isEnabled()) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getURI().getPath();
        ProbeProperties.Paths paths = probeProperties.getPaths();

        if (isTokenPath(path, paths)) {
            return handleTokenRequest(exchange, path, paths);
        }

        if (isDnsConfigPath(path, paths)) {
            return handleDnsConfigRequest(exchange, path, paths);
        }

        if (isUploadPath(path, paths)) {
            return handleUploadRequest(exchange, chain, path, paths);
        }

        if (isH5UploadPath(path, paths)) {
            return handleH5UploadRequest(exchange, chain);
        }

        return chain.filter(exchange);
    }

    private boolean isTokenPath(String path, ProbeProperties.Paths paths) {
        return path.equals(paths.getIosTokenPath()) || path.equals(paths.getAndroidTokenPath());
    }

    private boolean isDnsConfigPath(String path, ProbeProperties.Paths paths) {
        return path.equals(paths.getIosDnsConfigPath()) || path.equals(paths.getAndroidDnsConfigPath());
    }

    private boolean isUploadPath(String path, ProbeProperties.Paths paths) {
        return path.equals(paths.getIosUploadPath()) || path.equals(paths.getAndroidUploadPath());
    }

    private boolean isH5UploadPath(String path, ProbeProperties.Paths paths) {
        return path.equals(paths.getH5UploadPath());
    }

    private String getPlatform(String path, ProbeProperties.Paths paths) {
        if (path.contains("/ios/")) {
            return "ios";
        } else if (path.contains("/android/")) {
            return "android";
        }
        return "unknown";
    }

    private Mono<Void> handleTokenRequest(ServerWebExchange exchange, String path, 
                                          ProbeProperties.Paths paths) {
        if (!probeProperties.isTokenEnabled()) {
            return returnGone(exchange);
        }

        String clientIp = getClientIp(exchange);
        String platform = getPlatform(path, paths);

        return rateLimitService.allowProbeRequest(clientIp, "token")
                .flatMap(allowed -> {
                    if (!allowed) {
                        return returnNoContent(exchange);
                    }
                    return readRequestBody(exchange)
                            .flatMap(body -> processTokenRequest(exchange, body, platform, clientIp));
                });
    }

    private Mono<Void> processTokenRequest(ServerWebExchange exchange, String encryptedBody, 
                                           String platform, String clientIp) {
        try {
            if (encryptedBody == null || encryptedBody.isEmpty() || encryptedBody.length() > MAX_BODY_SIZE) {
                return returnNoContent(exchange);
            }

            String decryptedBody = AesUtil.decrypt(encryptedBody, probeProperties.getAesKey());
            if (decryptedBody == null) {
                return returnNoContent(exchange);
            }

            TokenRequest request = JSON.parseObject(decryptedBody, TokenRequest.class);
            if (request == null || StrUtil.isBlank(request.getDeviceId()) 
                    || request.getDeviceId().length() > 128) {
                return returnNoContent(exchange);
            }

            return tokenService.generateToken(platform, request.getDeviceId(), clientIp)
                    .flatMap(token -> {
                        TokenResponse response = new TokenResponse();
                        response.setToken(token);
                        response.setExpiresIn(probeProperties.getTokenTtlMinutes() * 60L);

                        String responseJson = JSON.toJSONString(response);
                        String encryptedResponse = AesUtil.encrypt(responseJson, 
                                probeProperties.getAesKey());

                        return writeResponse(exchange, encryptedResponse);
                    })
                    .switchIfEmpty(returnNoContent(exchange));
        } catch (Exception e) {
            log.error("Token request processing error: {}", e.getMessage());
            return returnNoContent(exchange);
        }
    }

    private Mono<Void> handleDnsConfigRequest(ServerWebExchange exchange, String path, 
                                               ProbeProperties.Paths paths) {
        if (!probeProperties.isDnsConfigEnabled()) {
            return returnGone(exchange);
        }

        String clientIp = getClientIp(exchange);
        String token = exchange.getRequest().getHeaders().getFirst(HEADER_X_TOKEN);

        if (StrUtil.isBlank(token) || token.length() > MAX_TOKEN_LENGTH) {
            return returnNoContent(exchange);
        }

        return rateLimitService.allowProbeRequest(clientIp, "dns-config")
                .flatMap(allowed -> {
                    if (!allowed) {
                        return returnNoContent(exchange);
                    }
                    return tokenService.validateToken(token, clientIp);
                })
                .flatMap(tokenInfo -> {
                    DnsConfigResponse response = buildDnsConfigResponse();

                    String responseJson = JSON.toJSONString(response);
                    String encryptedResponse = AesUtil.encrypt(responseJson, 
                            probeProperties.getAesKey());

                    if (encryptedResponse == null) {
                        return returnNoContent(exchange);
                    }
                    return writeResponse(exchange, encryptedResponse);
                })
                .switchIfEmpty(Mono.defer(() -> returnNoContent(exchange)));
    }

    private Mono<Void> handleUploadRequest(ServerWebExchange exchange, GatewayFilterChain chain,
                                           String path, ProbeProperties.Paths paths) {
        if (!probeProperties.isUploadEnabled()) {
            return returnGone(exchange);
        }

        String clientIp = getClientIp(exchange);

        return rateLimitService.allowProbeRequest(clientIp, "upload")
                .flatMap(allowed -> {
                    if (!allowed) {
                        return returnNoContent(exchange);
                    }
                    return validateAndForwardUpload(exchange, chain);
                });
    }

    private Mono<Void> handleH5UploadRequest(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!probeProperties.isH5UploadEnabled()) {
            return returnGone(exchange);
        }

        String clientIp = getClientIp(exchange);

        return rateLimitService.allowProbeRequest(clientIp, "h5-upload")
                .flatMap(allowed -> {
                    if (!allowed) {
                        return returnNoContent(exchange);
                    }
                    return forwardH5Upload(exchange, chain, clientIp);
                });
    }

    private Mono<Void> forwardH5Upload(ServerWebExchange exchange, GatewayFilterChain chain, String clientIp) {
        return readRequestBodyBytes(exchange)
                .flatMap(bodyBytes -> {
                    if (bodyBytes.length == 0 || bodyBytes.length > MAX_BODY_SIZE) {
                        return returnNoContent(exchange);
                    }

                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header("X-Probe-Validated", "true")
                            .header("X-Probe-Platform", "h5")
                            .header("X-Probe-Client-IP", clientIp)
                            .build();

                    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bodyBytes);
                    Flux<DataBuffer> cachedBody = Flux.just(buffer);

                    ServerHttpRequest newRequest = new CachedBodyServerHttpRequest(mutatedRequest, cachedBody);

                    return chain.filter(exchange.mutate().request(newRequest).build());
                });
    }

    private Mono<Void> validateAndForwardUpload(ServerWebExchange exchange, 
                                                 GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        HttpHeaders headers = request.getHeaders();

        String ts = headers.getFirst(HEADER_X_TS);
        String nonce = headers.getFirst(HEADER_X_NONCE);
        String sign = headers.getFirst(HEADER_X_SIGN);
        String token = headers.getFirst(HEADER_X_TOKEN);

        if (StrUtil.isBlank(ts) || StrUtil.isBlank(nonce) || 
            StrUtil.isBlank(sign) || StrUtil.isBlank(token)) {
            return returnNoContent(exchange);
        }

        if (!isValidHeaderLength(ts, nonce, sign, token)) {
            return returnNoContent(exchange);
        }

        if (!isTimestampValid(ts)) {
            return returnNoContent(exchange);
        }

        String clientIp = getClientIp(exchange);
        return tokenService.validateToken(token, clientIp)
                .flatMap(tokenInfo -> validateHmacAndForward(exchange, chain, ts, nonce, sign))
                .switchIfEmpty(Mono.defer(() -> returnNoContent(exchange)));
    }

    private Mono<Void> validateHmacAndForward(ServerWebExchange exchange, GatewayFilterChain chain,
                                               String ts, String nonce, String sign) {
        return readRequestBodyBytes(exchange)
                .flatMap(bodyBytes -> {
                    if (bodyBytes.length == 0) {
                        return returnNoContent(exchange);
                    }

                    String bodyHash = HmacUtil.sha256Hash(bodyBytes);
                    if (bodyHash == null) {
                        return returnNoContent(exchange);
                    }
                    
                    if (!HmacUtil.validateHmac(ts, nonce, bodyHash, sign, 
                            probeProperties.getHmacSecret())) {
                        return returnNoContent(exchange);
                    }

                    return nonceService.tryUseNonce(nonce)
                            .flatMap(success -> {
                                if (!success) {
                                    return returnNoContent(exchange);
                                }

                                String clientIp = getClientIp(exchange);
                                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                        .header("X-Probe-Validated", "true")
                                        .header("X-Probe-Platform", 
                                                getPlatform(exchange.getRequest().getURI().getPath(), 
                                                           probeProperties.getPaths()))
                                        .header("X-Probe-Client-IP", clientIp)
                                        .build();

                                DataBuffer buffer = exchange.getResponse().bufferFactory()
                                        .wrap(bodyBytes);
                                Flux<DataBuffer> cachedBody = Flux.just(buffer);

                                ServerHttpRequest newRequest = new CachedBodyServerHttpRequest(
                                        mutatedRequest, cachedBody);

                                return chain.filter(exchange.mutate().request(newRequest).build());
                            });
                });
    }

    private DnsConfigResponse buildDnsConfigResponse() {
        DnsConfigResponse response = new DnsConfigResponse();
        response.setDnsServers(new java.util.ArrayList<>(probeProperties.getProbeDnsServers()));

        java.util.Map<String, ProbeProperties.DomainCategory> categories = 
                new java.util.HashMap<>(probeProperties.getDomainCategories());
        
        categories.forEach((key, category) -> {
            if (category != null) {
                DnsConfigResponse.DomainCategoryDto dto = new DnsConfigResponse.DomainCategoryDto();
                dto.setCategoryKey(key);
                dto.setName(category.getName());
                dto.setDescription(category.getDescription());
                dto.setDomains(category.getDomains() != null ? 
                        new java.util.ArrayList<>(category.getDomains()) : new java.util.ArrayList<>());
                response.getCategories().add(dto);
            }
        });

        return response;
    }

    private boolean isValidHeaderLength(String ts, String nonce, String sign, String token) {
        return ts.length() <= MAX_TS_LENGTH &&
               nonce.length() <= MAX_NONCE_LENGTH &&
               sign.length() <= MAX_SIGN_LENGTH &&
               token.length() <= MAX_TOKEN_LENGTH;
    }

    private boolean isTimestampValid(String ts) {
        try {
            long timestamp = Long.parseLong(ts);
            long now = System.currentTimeMillis();
            long diff = Math.abs(now - timestamp);
            long maxDiff = probeProperties.getTimestampValidMinutes() * 60 * 1000L;
            return diff <= maxDiff;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private Mono<String> readRequestBody(ServerWebExchange exchange) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    int size = dataBuffer.readableByteCount();
                    if (size > MAX_BODY_SIZE) {
                        DataBufferUtils.release(dataBuffer);
                        return Mono.empty();
                    }
                    byte[] bytes = new byte[size];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return Mono.just(new String(bytes, StandardCharsets.UTF_8));
                })
                .defaultIfEmpty("");
    }

    private Mono<byte[]> readRequestBodyBytes(ServerWebExchange exchange) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    int size = dataBuffer.readableByteCount();
                    if (size > MAX_BODY_SIZE) {
                        DataBufferUtils.release(dataBuffer);
                        return Mono.empty();
                    }
                    byte[] bytes = new byte[size];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return Mono.just(bytes);
                })
                .defaultIfEmpty(new byte[0]);
    }

    private Mono<Void> writeResponse(ServerWebExchange exchange, String body) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.OK);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    private Mono<Void> returnNoContent(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.NO_CONTENT);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> returnGone(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.GONE);
        return exchange.getResponse().setComplete();
    }

    private String getClientIp(ServerWebExchange exchange) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        String ip = headers.getFirst("X-Real-IP");
        if (isValidIp(ip)) {
            return ip.trim();
        }
        ip = headers.getFirst("X-Forwarded-For");
        if (ip != null && !ip.isEmpty()) {
            String firstIp = ip.split(",")[0].trim();
            if (isValidIp(firstIp)) {
                return firstIp;
            }
        }
        if (exchange.getRequest().getRemoteAddress() != null) {
            return exchange.getRequest().getRemoteAddress().getAddress().getHostAddress();
        }
        return "unknown";
    }

    private boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty() || ip.length() > 45) {
            return false;
        }
        return ip.matches("^[0-9a-fA-F.:]+$");
    }

    @Override
    public int getOrder() {
        return -200;
    }
}
