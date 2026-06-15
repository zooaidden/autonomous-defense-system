package com.acd.defense.service;

import com.acd.defense.domain.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class DefenseOrchestratorService {
    private final AgentClient agentClient;
    private final VerificationService verificationService;
    private final ExecutionService executionService;

    public DefenseOrchestratorService(AgentClient agentClient, VerificationService verificationService, ExecutionService executionService) {
        this.agentClient = agentClient;
        this.verificationService = verificationService;
        this.executionService = executionService;
    }

    public DefenseLoopResult runLoop(SecurityEvent input) {
        SecurityEvent normalized = normalize(input);
        DebateResponse debateResponse = agentClient.debate(normalized);
        VerificationResult verificationResult = verificationService.verify(normalized, debateResponse.strategy());

        ExecutionRecord executionRecord = null;
        if (verificationResult.passed()) {
            executionRecord = executionService.execute(debateResponse.strategy());
        }

        return new DefenseLoopResult(
                normalized,
                debateResponse.debateState(),
                debateResponse.strategy(),
                verificationResult,
                executionRecord
        );
    }

    public SecurityEvent normalize(SecurityEvent input) {
        Map<String, Object> attrs = new HashMap<>(input.attributes() == null ? Map.of() : input.attributes());
        attrs.putIfAbsent("normalized", true);
        attrs.putIfAbsent("assetTag", "normal-service");
        return new SecurityEvent(
                input.eventId() == null ? UUID.randomUUID().toString() : input.eventId(),
                input.source(),
                input.eventType(),
                input.severity() == null ? "MEDIUM" : input.severity(),
                input.timestamp() == null ? Instant.now() : input.timestamp(),
                attrs
        );
    }
}
