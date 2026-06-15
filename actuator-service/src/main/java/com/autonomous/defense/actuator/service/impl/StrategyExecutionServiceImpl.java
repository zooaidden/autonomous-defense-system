package com.autonomous.defense.actuator.service.impl;

import com.autonomous.defense.actuator.adapter.ActionAdapter;
import com.autonomous.defense.actuator.adapter.impl.AlertAdapter;
import com.autonomous.defense.actuator.dto.DefenseStrategyRequest;
import com.autonomous.defense.actuator.exception.BusinessException;
import com.autonomous.defense.actuator.model.ExecutionRecord;
import com.autonomous.defense.actuator.model.ExecutionStatus;
import com.autonomous.defense.actuator.model.RollbackStatus;
import com.autonomous.defense.actuator.repository.ExecutionRecordRepository;
import com.autonomous.defense.actuator.rollback.RollbackManager;
import com.autonomous.defense.actuator.service.StrategyExecutionService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Service
@RequiredArgsConstructor
public class StrategyExecutionServiceImpl implements StrategyExecutionService {
    private final AlertAdapter alertAdapter;
    private final List<ActionAdapter> adapters;
    private final ExecutionRecordRepository repository;
    private final RollbackManager rollbackManager;
    private final ObjectMapper objectMapper;

    // Identifier allow-list shared with K8sAdapter so values that end up
    // in YAML / log lines cannot include shell metacharacters, newlines or
    // YAML control characters.
    private static final Pattern SAFE_IDENTIFIER = Pattern.compile("^[A-Za-z0-9._-]{1,128}$");

    @Override
    public ExecutionRecord execute(DefenseStrategyRequest request) {
        String executionId = "exe-" + UUID.randomUUID();
        boolean dryRun = !Boolean.FALSE.equals(request.getDryRun());
        log.info(
                "Receive strategy. strategyId={} executionId={} dryRun={} actions={}",
                request.getStrategyId(),
                executionId,
                dryRun,
                request.getActions() == null ? 0 : request.getActions().size());
        Instant start = Instant.now();

        // Upstream-trust validation: even when the call is signed by
        // agent-brain, this service re-validates inputs because the upstream
        // chain can be bypassed. Any failure aborts the run without touching
        // an adapter.
        try {
            validateStrategy(request);
        } catch (BusinessException ex) {
            log.warn("Strategy rejected before execution. strategyId={}, reason={}",
                    request.getStrategyId(), ex.getMessage());
            ExecutionRecord rejected = ExecutionRecord.builder()
                    .executionId(executionId)
                    .strategyId(request.getStrategyId())
                    .status(ExecutionStatus.FAILED)
                    .startTime(start)
                    .endTime(Instant.now())
                    .resultMessage("Rejected by pre-execution validation: " + ex.getMessage())
                    .rollbackStatus(RollbackStatus.NOT_REQUIRED)
                    .ttl(request.getTtl())
                    .generatedArtifacts(new ArrayList<>())
                    .strategySnapshot(strategySnapshot(request))
                    .failureReason(ex.getMessage())
                    .rollbackReason(null)
                    .rollbackTrigger(null)
                    .rollbackAt(null)
                    .build();
            return repository.save(rejected);
        }

        try {
            List<Map<String, Object>> artifacts = new ArrayList<>();
            for (DefenseStrategyRequest.DefenseActionDTO action : request.getActions()) {
                // ALERT_ONLY is handled explicitly so execution never fails with "No adapter found".
                if ("ALERT_ONLY".equalsIgnoreCase(action.getType())) {
                    artifacts.add(alertAdapter.generateConfig(action, request));
                    continue;
                }
                ActionAdapter adapter = resolveAdapter(action.getType());
                Map<String, Object> artifact = adapter.generateConfig(action, request);
                artifacts.add(artifact);
            }

            String resultMessage = dryRun
                    ? "Dry-run completed: artifacts generated, no real apply (demo-only persistence is in-memory)"
                    : "Real-run completed (in-memory persistence; production deployments must wire a durable repository)";
            ExecutionRecord record = ExecutionRecord.builder()
                    .executionId(executionId)
                    .strategyId(request.getStrategyId())
                    .status(ExecutionStatus.SUCCEEDED)
                    .startTime(start)
                    .endTime(Instant.now())
                    .resultMessage(resultMessage)
                    .rollbackStatus(request.getTtl() != null && request.getTtl() > 0 ? RollbackStatus.AVAILABLE : RollbackStatus.NOT_REQUIRED)
                    .ttl(request.getTtl())
                    .generatedArtifacts(artifacts)
                    .strategySnapshot(strategySnapshot(request))
                    .failureReason(null)
                    .rollbackReason(null)
                    .rollbackTrigger(null)
                    .rollbackAt(null)
                    .build();
            return repository.save(record);
        } catch (Exception ex) {
            log.error("Execution failed. strategyId={}, reason={}", request.getStrategyId(), ex.getMessage(), ex);
            ExecutionRecord failed = ExecutionRecord.builder()
                    .executionId(executionId)
                    .strategyId(request.getStrategyId())
                    .status(ExecutionStatus.FAILED)
                    .startTime(start)
                    .endTime(Instant.now())
                    .resultMessage("Simulated execution failed")
                    .rollbackStatus(RollbackStatus.FAILED)
                    .ttl(request.getTtl())
                    .generatedArtifacts(new ArrayList<>())
                    .strategySnapshot(strategySnapshot(request))
                    .failureReason(ex.getMessage())
                    .rollbackReason(null)
                    .rollbackTrigger(null)
                    .rollbackAt(null)
                    .build();
            return repository.save(failed);
        }
    }

    @Override
    public ExecutionRecord rollback(String executionId) {
        return rollbackManager.manualRollback(executionId);
    }

    @Override
    public List<ExecutionRecord> listExecutions() {
        return repository.findAll();
    }

    @Override
    public ExecutionRecord getExecution(String executionId) {
        return repository.findById(executionId)
                .orElseThrow(() -> new com.autonomous.defense.actuator.exception.ResourceNotFoundException("Execution not found: " + executionId));
    }

    private ActionAdapter resolveAdapter(String actionType) {
        return adapters.stream()
                .filter(adapter -> adapter.supports(actionType))
                .findFirst()
                .orElseThrow(() -> new BusinessException("No adapter found for action type: " + actionType));
    }

    private Map<String, Object> strategySnapshot(DefenseStrategyRequest request) {
        return objectMapper.convertValue(request, new TypeReference<>() {
        });
    }

    // Validate fields whose values eventually land in generated YAML or in
    // log lines. Adapters down the line trust these checks; centralising
    // them here avoids reimplementing the same allow-list in every adapter.
    private void validateStrategy(DefenseStrategyRequest request) {
        if (request.getStrategyId() == null || !SAFE_IDENTIFIER.matcher(request.getStrategyId()).matches()) {
            throw new BusinessException("strategyId must match [A-Za-z0-9._-]{1,128}");
        }
        if (request.getActions() == null || request.getActions().isEmpty()) {
            throw new BusinessException("strategy actions[] is required and must be non-empty");
        }
        if (request.getRollbackPlan() == null
                || request.getRollbackPlan().getPlanId() == null
                || request.getRollbackPlan().getPlanId().isBlank()) {
            // Rollback plan is mandatory: actuator-service must be able to
            // tell the operator how to revert the change. Strategies without
            // one are rejected even when the upstream marked them low-risk.
            throw new BusinessException("rollbackPlan.planId is required (strategy must be revertible)");
        }
        for (DefenseStrategyRequest.DefenseActionDTO action : request.getActions()) {
            if (action.getType() == null || !SAFE_IDENTIFIER.matcher(action.getType()).matches()) {
                throw new BusinessException("action.type must match [A-Za-z0-9._-]{1,128}");
            }
            if (action.getTarget() == null || !SAFE_IDENTIFIER.matcher(action.getTarget()).matches()) {
                throw new BusinessException(
                        "action.target must match [A-Za-z0-9._-]{1,128} (got: '"
                                + truncate(action.getTarget(), 80) + "')");
            }
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) {
            return "<null>";
        }
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}

