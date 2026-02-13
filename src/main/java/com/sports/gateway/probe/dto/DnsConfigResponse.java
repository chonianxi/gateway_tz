package com.sports.gateway.probe.dto;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class DnsConfigResponse {
    private List<DomainCategoryDto> categories = new ArrayList<>();
    private List<String> dnsServers = new ArrayList<>();
    private String monitorUsers;  // 需要监控的用户列表 (用,隔开)

    @Data
    public static class DomainCategoryDto {
        private String categoryKey;
        private String name;
        private String description;
        private List<String> domains = new ArrayList<>();
    }
}
