package com.autonomous.defense.actuator.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "app.rollback")
public class RollbackProperties {
    private boolean schedulerEnabled = true;
    private long pollIntervalMs = 5000;
}

