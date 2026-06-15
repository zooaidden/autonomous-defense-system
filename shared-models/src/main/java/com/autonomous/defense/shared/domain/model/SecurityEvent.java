package com.autonomous.defense.shared.domain.model;

import com.autonomous.defense.shared.domain.enums.DomainEnums;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record SecurityEvent(
        String eventId,
        Instant timestamp,
        DomainEnums.SourceType sourceType,
        String subject,
        String action,
        String object,
        Map<String, Object> context,
        DomainEnums.Severity severity,
        double riskScore,
        List<String> labels
) {
}

