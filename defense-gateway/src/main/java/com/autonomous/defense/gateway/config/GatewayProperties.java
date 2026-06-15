package com.autonomous.defense.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "app")
public class GatewayProperties {
    private Kafka kafka = new Kafka();

    @Data
    public static class Kafka {
        private String eventTopic = "security.events";
    }
}

