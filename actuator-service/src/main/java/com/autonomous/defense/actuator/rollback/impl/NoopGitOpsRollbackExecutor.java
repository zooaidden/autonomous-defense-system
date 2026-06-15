package com.autonomous.defense.actuator.rollback.impl;

import com.autonomous.defense.actuator.model.ExecutionRecord;
import com.autonomous.defense.actuator.rollback.GitOpsRollbackExecutor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class NoopGitOpsRollbackExecutor implements GitOpsRollbackExecutor {
    @Override
    public boolean supports(ExecutionRecord record) {
        return true;
    }

    @Override
    public void executeRollback(ExecutionRecord record) {
        log.info("GitOps rollback placeholder invoked. executionId={}, strategyId={}", record.executionId(), record.strategyId());
    }
}

