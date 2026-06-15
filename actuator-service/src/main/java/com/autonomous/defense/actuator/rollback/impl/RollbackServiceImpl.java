package com.autonomous.defense.actuator.rollback.impl;

import com.autonomous.defense.actuator.exception.BusinessException;
import com.autonomous.defense.actuator.exception.ResourceNotFoundException;
import com.autonomous.defense.actuator.model.ExecutionRecord;
import com.autonomous.defense.actuator.model.RollbackStatus;
import com.autonomous.defense.actuator.model.RollbackTrigger;
import com.autonomous.defense.actuator.repository.ExecutionRecordRepository;
import com.autonomous.defense.actuator.rollback.GitOpsRollbackExecutor;
import com.autonomous.defense.actuator.rollback.RollbackService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class RollbackServiceImpl implements RollbackService {
    private final ExecutionRecordRepository repository;
    private final List<GitOpsRollbackExecutor> gitOpsExecutors;

    @Override
    public ExecutionRecord rollback(String executionId, RollbackTrigger trigger, String reason) {
        ExecutionRecord existing = repository.findById(executionId)
                .orElseThrow(() -> new ResourceNotFoundException("Execution not found: " + executionId));

        if (existing.rollbackStatus() == RollbackStatus.SUCCEEDED) {
            log.info("Skip rollback, already succeeded. executionId={}", executionId);
            return existing;
        }
        if (existing.rollbackStatus() != RollbackStatus.AVAILABLE && existing.rollbackStatus() != RollbackStatus.FAILED) {
            throw new BusinessException("Execution not rollbackable, current rollbackStatus=" + existing.rollbackStatus());
        }

        ExecutionRecord running = existing.withRollback(RollbackStatus.RUNNING, reason, trigger, Instant.now());
        repository.save(running);
        log.info(
                "Rollback started. executionId={}, trigger={}, reason={}, targetAdapters={}",
                executionId,
                trigger,
                reason,
                adapterTargets(existing.generatedArtifacts())
        );

        try {
            if (trigger == RollbackTrigger.GITOPS) {
                GitOpsRollbackExecutor executor = gitOpsExecutors.stream()
                        .filter(e -> e.supports(existing))
                        .findFirst()
                        .orElseThrow(() -> new BusinessException("No GitOps rollback executor available"));
                executor.executeRollback(existing);
            }
            ExecutionRecord success = running.withRollback(RollbackStatus.SUCCEEDED, reason, trigger, Instant.now());
            repository.save(success);
            log.info("Rollback succeeded. executionId={}, strategyId={}", success.executionId(), success.strategyId());
            return success;
        } catch (Exception ex) {
            ExecutionRecord failed = ExecutionRecord.builder()
                    .executionId(running.executionId())
                    .strategyId(running.strategyId())
                    .status(running.status())
                    .startTime(running.startTime())
                    .endTime(running.endTime())
                    .resultMessage(running.resultMessage())
                    .rollbackStatus(RollbackStatus.FAILED)
                    .ttl(running.ttl())
                    .generatedArtifacts(running.generatedArtifacts())
                    .strategySnapshot(running.strategySnapshot())
                    .failureReason(running.failureReason())
                    .rollbackReason(reason + "; error=" + ex.getMessage())
                    .rollbackTrigger(trigger)
                    .rollbackAt(Instant.now())
                    .build();
            repository.save(failed);
            log.error("Rollback failed. executionId={}, reason={}", executionId, ex.getMessage(), ex);
            return failed;
        }
    }

    private List<String> adapterTargets(List<Map<String, Object>> artifacts) {
        return artifacts.stream()
                .map(item -> String.valueOf(item.getOrDefault("adapter", "unknown-adapter")))
                .toList();
    }
}

