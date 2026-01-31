package com.sports.gateway.probe.dto;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class DnsConfigResponse {
    private List<DomainCategoryDto> categories = new ArrayList<>();
    private List<String> dnsServers = new ArrayList<>();

    @Data
    public static class DomainCategoryDto {
        private String categoryKey;
        private String name;
        private String description;
        private List<String> domains = new ArrayList<>();
    }
}
