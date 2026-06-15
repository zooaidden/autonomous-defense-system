package com.acd.defense.domain;

public record DefenseLoopResult(
        SecurityEvent event,
        DebateState debateState,
        DefenseStrategy strategy,
        VerificationResult verificationResult,
        ExecutionRecord executionRecord
) {
}
