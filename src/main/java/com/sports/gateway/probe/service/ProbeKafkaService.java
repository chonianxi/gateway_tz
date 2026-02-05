package com.sports.gateway.probe.service;

import com.alibaba.fastjson.JSON;
import com.sports.gateway.config.properties.ProbeProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

@Slf4j
@Service
public class ProbeKafkaService {

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ProbeProperties probeProperties;

    public ProbeKafkaService(KafkaTemplate<String, String> kafkaTemplate,
                             ProbeProperties probeProperties) {
        this.kafkaTemplate = kafkaTemplate;
        this.probeProperties = probeProperties;
    }

    public void sendProbeData(String appId, String platform, String clientIp, Map<String, Object> probeData) {
        try {
            ProbeMessage message = new ProbeMessage();
            message.setAppId(appId);
            message.setPlatform(platform);
            message.setClientIp(clientIp);
            message.setTimestamp(System.currentTimeMillis());
            message.setData(probeData);

            String jsonMessage = JSON.toJSONString(message);
            String topic = probeProperties.getKafkaTopic();

            CompletableFuture<SendResult<String, String>> future = kafkaTemplate.send(topic, appId, jsonMessage);
            
            future.whenComplete((result, ex) -> {
                if (ex != null) {
                    log.error("Failed to send probe data to Kafka: appId={}, error={}", appId, ex.getMessage());
                } else {
                    log.debug("Probe data sent to Kafka: appId={}, partition={}, offset={}", 
                            appId, result.getRecordMetadata().partition(), result.getRecordMetadata().offset());
                }
            });
        } catch (Exception e) {
            log.error("Error sending probe data to Kafka: appId={}, error={}", appId, e.getMessage());
        }
    }

    public void sendProbeDataSync(String appId, String platform, String clientIp, Map<String, Object> probeData) {
        try {
            ProbeMessage message = new ProbeMessage();
            message.setAppId(appId);
            message.setPlatform(platform);
            message.setClientIp(clientIp);
            message.setTimestamp(System.currentTimeMillis());
            message.setData(probeData);

            String jsonMessage = JSON.toJSONString(message);
            String topic = probeProperties.getKafkaTopic();

            SendResult<String, String> result = kafkaTemplate.send(topic, appId, jsonMessage).get();
            log.debug("Probe data sent to Kafka: appId={}, partition={}, offset={}", 
                    appId, result.getRecordMetadata().partition(), result.getRecordMetadata().offset());
        } catch (Exception e) {
            log.error("Error sending probe data to Kafka: appId={}, error={}", appId, e.getMessage());
            throw new RuntimeException("Failed to send to Kafka", e);
        }
    }

    @lombok.Data
    public static class ProbeMessage {
        private String appId;
        private String platform;
        private String clientIp;
        private long timestamp;
        private Map<String, Object> data;
    }
}
