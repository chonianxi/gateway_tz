package com.sports.gateway.probe.dto;

import lombok.Data;

@Data
public class TokenResponse {
    private String token;
    private long expiresIn;
}
