package com.autonomous.defense.shared.domain.model;

import java.util.List;

public record VerificationResult(
        boolean passed,
        List<String> violatedConstraints,
        List<String> warnings,
        String reason,
        List<String> suggestedFixes
) {
}

