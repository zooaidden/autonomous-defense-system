package com.autonomous.defense.shared.domain.model;

import com.autonomous.defense.shared.domain.enums.DomainEnums;

import java.time.Instant;

public record ExecutionRecord(
        String executionId,
        String strategyId,
        DomainEnums.ExecutorType executorType,
        DomainEnums.ExecutionStatus status,
        Instant startTime,
        Instant endTime,
        String resultMessage,
        DomainEnums.RollbackStatus rollbackStatus
) {
}

