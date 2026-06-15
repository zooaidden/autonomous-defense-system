package com.autonomous.defense.actuator.rollback;

import com.autonomous.defense.actuator.config.RollbackProperties;
import com.autonomous.defense.actuator.model.ExecutionRecord;
import com.autonomous.defense.actuator.model.RollbackTrigger;
import com.autonomous.defense.actuator.repository.ExecutionRecordRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class RollbackManager {
    private final ExecutionRecordRepository repository;
    private final RollbackService rollbackService;
    private final RollbackProperties properties;

    public ExecutionRecord manualRollback(String executionId) {
        return rollbackService.rollback(executionId, RollbackTrigger.MANUAL, "manual_rollback_requested");
    }

    @Scheduled(fixedDelayString = "${app.rollback.poll-interval-ms:5000}")
    public void processAutoRollback() {
        if (!properties.isSchedulerEnabled()) {
            return;
        }
        long now = Instant.now().getEpochSecond();
        List<ExecutionRecord> candidates = repository.findAutoRollbackCandidates(now);
        for (ExecutionRecord record : candidates) {
            log.info(
                    "TTL rollback due. executionId={}, strategyId={}, ttl={}, startTime={}",
                    record.executionId(),
                    record.strategyId(),
                    record.ttl(),
                    record.startTime()
            );
            rollbackService.rollback(record.executionId(), RollbackTrigger.TTL_AUTO, "ttl_expired");
        }
    }
}

