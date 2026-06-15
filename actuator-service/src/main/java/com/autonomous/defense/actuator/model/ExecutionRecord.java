package com.autonomous.defense.actuator.model;

import lombok.Builder;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Builder
public record ExecutionRecord(
        String executionId,
        String strategyId,
        ExecutionStatus status,
        Instant startTime,
        Instant endTime,
        String resultMessage,
        RollbackStatus rollbackStatus,
        Long ttl,
        List<Map<String, Object>> generatedArtifacts,
        Map<String, Object> strategySnapshot,
        String failureReason,
        String rollbackReason,
        RollbackTrigger rollbackTrigger,
        Instant rollbackAt
) {
    public ExecutionRecord withStatus(ExecutionStatus newStatus, String newMessage, Instant newEndTime, RollbackStatus newRollbackStatus) {
        return ExecutionRecord.builder()
                .executionId(executionId)
                .strategyId(strategyId)
                .status(newStatus)
                .startTime(startTime)
                .endTime(newEndTime)
                .resultMessage(newMessage)
                .rollbackStatus(newRollbackStatus)
                .ttl(ttl)
                .generatedArtifacts(new ArrayList<>(generatedArtifacts))
                .strategySnapshot(strategySnapshot)
                .failureReason(failureReason)
                .rollbackReason(rollbackReason)
                .rollbackTrigger(rollbackTrigger)
                .rollbackAt(rollbackAt)
                .build();
    }

    public ExecutionRecord withRollback(RollbackStatus newRollbackStatus, String reason, RollbackTrigger trigger, Instant rollbackTime) {
        return ExecutionRecord.builder()
                .executionId(executionId)
                .strategyId(strategyId)
                .status(status)
                .startTime(startTime)
                .endTime(endTime)
                .resultMessage(resultMessage)
                .rollbackStatus(newRollbackStatus)
                .ttl(ttl)
                .generatedArtifacts(new ArrayList<>(generatedArtifacts))
                .strategySnapshot(strategySnapshot)
                .failureReason(failureReason)
                .rollbackReason(reason)
                .rollbackTrigger(trigger)
                .rollbackAt(rollbackTime)
                .build();
    }
}

