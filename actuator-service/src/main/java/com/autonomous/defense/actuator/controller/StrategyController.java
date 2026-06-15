package com.autonomous.defense.actuator.controller;

import com.autonomous.defense.actuator.common.ApiResponse;
import com.autonomous.defense.actuator.dto.DefenseStrategyRequest;
import com.autonomous.defense.actuator.model.ExecutionRecord;
import com.autonomous.defense.actuator.service.StrategyExecutionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class StrategyController {
    private final StrategyExecutionService strategyExecutionService;

    @GetMapping("/health")
    public ResponseEntity<ApiResponse<Map<String, String>>> health() {
        return ResponseEntity.ok(ApiResponse.ok(Map.of("status", "UP", "service", "actuator-service")));
    }

    @PostMapping("/strategies/execute")
    public ResponseEntity<ApiResponse<ExecutionRecord>> execute(@Valid @RequestBody DefenseStrategyRequest request) {
        log.info("Receive execute request. strategyId={}", request.getStrategyId());
        return ResponseEntity.ok(ApiResponse.ok(strategyExecutionService.execute(request)));
    }

    @PostMapping("/strategies/{id}/rollback")
    public ResponseEntity<ApiResponse<ExecutionRecord>> rollback(@PathVariable("id") String id) {
        return ResponseEntity.ok(ApiResponse.ok(strategyExecutionService.rollback(id)));
    }

    @GetMapping("/executions")
    public ResponseEntity<ApiResponse<List<ExecutionRecord>>> listExecutions() {
        return ResponseEntity.ok(ApiResponse.ok(strategyExecutionService.listExecutions()));
    }

    @GetMapping("/executions/{id}")
    public ResponseEntity<ApiResponse<ExecutionRecord>> getExecution(@PathVariable("id") String id) {
        return ResponseEntity.ok(ApiResponse.ok(strategyExecutionService.getExecution(id)));
    }
}

