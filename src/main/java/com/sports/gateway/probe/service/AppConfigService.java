package com.sports.gateway.probe.service;

import com.sports.gateway.config.properties.ProbeProperties;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class AppConfigService {

    private final ProbeProperties probeProperties;
    private final Map<String, ProbeProperties.AppConfig> appConfigMap = new ConcurrentHashMap<>();

    public AppConfigService(ProbeProperties probeProperties) {
        this.probeProperties = probeProperties;
    }

    @PostConstruct
    public void init() {
        refreshAppConfigs();
    }

    public void refreshAppConfigs() {
        appConfigMap.clear();
        for (ProbeProperties.AppConfig app : probeProperties.getApps()) {
            if (app.isEnabled() && app.getAppId() != null) {
                appConfigMap.put(app.getAppId(), app);
                log.info("Loaded app config: appId={}, appName={}", app.getAppId(), app.getAppName());
            }
        }
        log.info("Total {} app configs loaded", appConfigMap.size());
    }

    public Optional<ProbeProperties.AppConfig> getAppConfig(String appId) {
        if (appId == null || appId.isBlank()) {
            return Optional.empty();
        }
        ProbeProperties.AppConfig config = appConfigMap.get(appId);
        if (config != null && config.isEnabled()) {
            return Optional.of(config);
        }
        return Optional.empty();
    }

    public String getAesKey(String appId) {
        return getAppConfig(appId)
                .map(ProbeProperties.AppConfig::getAesKey)
                .orElse(null);
    }

    public String getHmacSecret(String appId) {
        return getAppConfig(appId)
                .map(ProbeProperties.AppConfig::getHmacSecret)
                .orElse(null);
    }

    public boolean isValidAppId(String appId) {
        return getAppConfig(appId).isPresent();
    }
}
