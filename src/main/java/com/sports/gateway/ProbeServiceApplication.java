package com.sports.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties
public class ProbeServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(ProbeServiceApplication.class, args);
    }
}
