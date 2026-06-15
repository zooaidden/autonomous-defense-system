package com.autonomous.defense.actuator.service;

import com.autonomous.defense.actuator.dto.DefenseStrategyRequest;
import com.autonomous.defense.actuator.model.ExecutionRecord;

import java.util.List;

public interface StrategyExecutionService {
    ExecutionRecord execute(DefenseStrategyRequest request);

    ExecutionRecord rollback(String executionId);

    List<ExecutionRecord> listExecutions();

    ExecutionRecord getExecution(String executionId);
}

