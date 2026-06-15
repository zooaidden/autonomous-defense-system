package com.autonomous.defense.shared.domain.model;

import com.autonomous.defense.shared.domain.enums.DomainEnums;

import java.time.Instant;
import java.util.List;

public record DebateState(
        String debateId,
        SecurityEvent securityEvent,
        List<String> retrievedContext,
        DefenseStrategy plannerProposal,
        List<String> redTeamChallenges,
        DefenseStrategy revisedProposal,
        int round,
        DomainEnums.DebateStatus status,
        FinalDecision finalDecision,
        List<DebateTurn> history
) {
    public record FinalDecision(
            DomainEnums.DecisionType decision,
            String owner,
            String rationale,
            Instant decidedAt
    ) {
    }

    public record DebateTurn(
            int round,
            String actor,
            String message,
            Instant timestamp
    ) {
    }
}

