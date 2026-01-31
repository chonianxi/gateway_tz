package com.sports.gateway.probe.dto;

import lombok.Data;

@Data
public class ProbeTokenInfo {
    private String token;
    private String platform;
    private String deviceId;
    private String clientIp;
    private long createdAt;
}
