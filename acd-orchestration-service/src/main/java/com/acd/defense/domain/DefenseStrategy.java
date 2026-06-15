package com.acd.defense.domain;

import java.util.List;

public record DefenseStrategy(
        String strategyId,
        String strategyType,
        List<String> actions,
        String rationale,
        String riskLevel
) {
}
