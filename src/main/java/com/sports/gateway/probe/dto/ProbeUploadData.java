package com.sports.gateway.probe.dto;

import lombok.Data;

import java.util.List;

@Data
public class ProbeUploadData {
    private String deviceId;
    private String platform;
    private String appVersion;
    private String networkType;
    private String carrierName;
    private long timestamp;
    private List<ProbeResult> probeResults;

    @Data
    public static class ProbeResult {
        private String categoryKey;
        private String domain;
        private String dnsServer;
        private String resolvedIp;
        private int dnsLatency;
        private int tcpLatency;
        private int httpLatency;
        private int httpStatusCode;
        private int errorCode;
        private String errorMsg;
    }
}
