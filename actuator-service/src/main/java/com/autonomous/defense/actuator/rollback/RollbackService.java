package com.autonomous.defense.actuator.rollback;

import com.autonomous.defense.actuator.model.ExecutionRecord;
import com.autonomous.defense.actuator.model.RollbackTrigger;

public interface RollbackService {
    ExecutionRecord rollback(String executionId, RollbackTrigger trigger, String reason);
}

