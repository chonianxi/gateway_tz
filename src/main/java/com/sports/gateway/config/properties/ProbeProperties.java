package com.sports.gateway.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "probe")
public class ProbeProperties {

    private boolean enabled = true;

    private boolean tokenEnabled = true;

    private boolean dnsConfigEnabled = true;

    private boolean uploadEnabled = true;

    private boolean h5UploadEnabled = true;
    
    private String kafkaTopic = "probe_metadata";
    
    private List<AppConfig> apps = new ArrayList<>();
    
    @Data
    public static class AppConfig {
        private String appId;
        private String appName;
        private String aesKey;
        private String hmacSecret;
        private boolean enabled = true;
    }

    private int tokenTtlMinutes = 30;

    private int tokenMaxRequestsPerWindow = 100;

    private int tokenRequestWindowMinutes = 5;

    private int timestampValidMinutes = 5;

    private int ipRateLimitCount = 100;

    private int ipRateLimitWindowSeconds = 180;

    private int nonceCacheSize = 100000;

    private int nonceCacheExpireMinutes = 10;

    private Map<String, DomainCategory> domainCategories = new HashMap<>();

    private List<String> probeDnsServers = new ArrayList<>();

    @Data
    public static class DomainCategory {
        private String name;
        private String description;
        private List<String> domains = new ArrayList<>();
    }

    private Paths paths = new Paths();

    @Data
    public static class Paths {
        private String iosTokenPath = "/api/probe/ios/token";
        private String androidTokenPath = "/api/probe/android/token";
        private String iosDnsConfigPath = "/api/probe/ios/dns-config";
        private String androidDnsConfigPath = "/api/probe/android/dns-config";
        private String iosUploadPath = "/api/probe/ios/upload";
        private String androidUploadPath = "/api/probe/android/upload";
        private String h5UploadPath = "/api/probe/h5/upload";
    }
}
