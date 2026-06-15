package com.acd.defense.domain;

import jakarta.validation.constraints.NotBlank;

import java.time.Instant;
import java.util.Map;

public record SecurityEvent(
        String eventId,
        @NotBlank String source,
        @NotBlank String eventType,
        String severity,
        Instant timestamp,
        Map<String, Object> attributes
) {
}
