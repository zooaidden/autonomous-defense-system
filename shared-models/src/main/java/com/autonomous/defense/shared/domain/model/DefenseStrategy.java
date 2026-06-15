package com.autonomous.defense.shared.domain.model;

import com.autonomous.defense.shared.domain.enums.DomainEnums;

import java.util.List;
import java.util.Map;

public record DefenseStrategy(
        String strategyId,
        DomainEnums.ThreatType threatType,
        DomainEnums.TargetLayer targetLayer,
        List<DefenseAction> actions,
        StrategyScope scope,
        long ttl,
        RollbackPlan rollbackPlan,
        double confidence,
        DomainEnums.GeneratedBy generatedBy,
        boolean approved
) {
    public record DefenseAction(
            DomainEnums.ActionType type,
            String target,
            Map<String, Object> parameters
    ) {
    }

    public record StrategyScope(
            List<String> assets,
            List<String> namespaces,
            String tenantId
    ) {
    }

    public record RollbackPlan(
            String planId,
            List<String> steps,
            String triggerCondition
    ) {
    }
}

