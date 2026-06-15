package com.acd.defense.domain;

import java.time.Instant;
import java.util.List;

public record ExecutionRecord(
        String executionId,
        String strategyId,
        String targetType,
        List<String> appliedRules,
        String status,
        Instant executedAt,
        String rollbackToken
) {
}
