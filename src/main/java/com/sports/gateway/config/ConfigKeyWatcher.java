package com.sports.gateway.config;

import com.sports.gateway.config.properties.ProbeProperties;
import com.sports.gateway.probe.util.AesUtil;
import com.sports.gateway.probe.util.HmacUtil;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 配置密钥变更监控器
 * 定期检查aes-key和hmac-secret是否变化，变化时按appId维度清除缓存
 */
@Slf4j
@Component
@EnableScheduling
@RequiredArgsConstructor
public class ConfigKeyWatcher {

    private final ProbeProperties probeProperties;
    
    // 存储每个appId的密钥快照 (appId -> KeySnapshot)
    private final Map<String, KeySnapshot> keySnapshots = new ConcurrentHashMap<>();
    
    /**
     * 密钥快照
     */
    private record KeySnapshot(String aesKey, String hmacSecret) {}
    
    /**
     * 初始化时保存当前密钥快照
     */
    @PostConstruct
    public void init() {
        saveCurrentKeySnapshots();
        log.info("ConfigKeyWatcher initialized with {} app configs", keySnapshots.size());
    }
    
    /**
     * 每5秒检查一次密钥是否变化
     */
    @Scheduled(fixedDelay = 5000)
    public void checkKeyChanges() {
        if (probeProperties.getApps() == null) {
            return;
        }
        
        for (ProbeProperties.AppConfig app : probeProperties.getApps()) {
            if (app == null || app.getAppId() == null) {
                continue;
            }
            
            String appId = app.getAppId();
            String currentAesKey = app.getAesKey();
            String currentHmacSecret = app.getHmacSecret();
            
            KeySnapshot oldSnapshot = keySnapshots.get(appId);
            
            if (oldSnapshot == null) {
                // 新增的appId
                keySnapshots.put(appId, new KeySnapshot(currentAesKey, currentHmacSecret));
                log.info("New appId detected: {}", appId);
                continue;
            }
            
            boolean aesKeyChanged = !Objects.equals(oldSnapshot.aesKey(), currentAesKey);
            boolean hmacSecretChanged = !Objects.equals(oldSnapshot.hmacSecret(), currentHmacSecret);
            
            if (aesKeyChanged || hmacSecretChanged) {
                log.info("Key change detected for appId: {}, aesKey changed: {}, hmacSecret changed: {}", 
                        appId, aesKeyChanged, hmacSecretChanged);
                
                // 按appId维度清除缓存
                if (aesKeyChanged) {
                    AesUtil.invalidateKey(appId);
                    log.info("AES key cache invalidated for appId: {}", appId);
                }
                if (hmacSecretChanged) {
                    HmacUtil.invalidateKey(appId);
                    log.info("HMAC key cache invalidated for appId: {}", appId);
                }
                
                // 更新快照
                keySnapshots.put(appId, new KeySnapshot(currentAesKey, currentHmacSecret));
            }
        }
        
        // 检查是否有appId被删除
        keySnapshots.keySet().removeIf(appId -> {
            boolean exists = probeProperties.getApps().stream()
                    .anyMatch(app -> app != null && appId.equals(app.getAppId()));
            if (!exists) {
                AesUtil.invalidateKey(appId);
                HmacUtil.invalidateKey(appId);
                log.info("AppId removed: {}, caches invalidated", appId);
            }
            return !exists;
        });
    }
    
    /**
     * 保存当前所有密钥快照
     */
    private void saveCurrentKeySnapshots() {
        if (probeProperties.getApps() == null) {
            return;
        }
        
        for (ProbeProperties.AppConfig app : probeProperties.getApps()) {
            if (app != null && app.getAppId() != null) {
                keySnapshots.put(app.getAppId(), 
                        new KeySnapshot(app.getAesKey(), app.getHmacSecret()));
            }
        }
    }
}
