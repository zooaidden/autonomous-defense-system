package com.autonomous.defense.actuator.rollback;

import com.autonomous.defense.actuator.model.ExecutionRecord;

public interface GitOpsRollbackExecutor {
    boolean supports(ExecutionRecord record);

    void executeRollback(ExecutionRecord record);
}

