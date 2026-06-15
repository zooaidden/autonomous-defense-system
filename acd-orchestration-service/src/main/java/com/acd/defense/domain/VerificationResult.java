package com.acd.defense.domain;

import java.util.List;

public record VerificationResult(
        boolean passed,
        List<String> constraintsChecked,
        List<String> violations,
        String summary
) {
}
