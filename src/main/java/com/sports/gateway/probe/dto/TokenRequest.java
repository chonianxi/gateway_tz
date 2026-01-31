package com.sports.gateway.probe.dto;

import lombok.Data;

@Data
public class TokenRequest {
    private String deviceId;
    private String appVersion;
    private long ts;
}
