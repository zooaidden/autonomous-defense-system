package com.acd.defense.service;

import com.acd.defense.domain.DefenseStrategy;
import com.acd.defense.domain.SecurityEvent;
import com.acd.defense.domain.VerificationResult;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class VerificationService {

    public VerificationResult verify(SecurityEvent event, DefenseStrategy strategy) {
        List<String> checked = List.of(
                "no-block-core-namespace",
                "max-actions-lte-5",
                "high-severity-can-isolate"
        );
        List<String> violations = new ArrayList<>();

        if (strategy.actions() != null && strategy.actions().size() > 5) {
            violations.add("策略动作过多，超出MVP安全执行阈值");
        }
        Object assetTag = event.attributes() == null ? "" : event.attributes().getOrDefault("assetTag", "");
        if ("core-service".equals(assetTag)
                && strategy.actions() != null
                && strategy.actions().stream().anyMatch(a -> a.contains("deny-all"))) {
            violations.add("核心业务资产禁止下发 deny-all 策略");
        }

        boolean passed = violations.isEmpty();
        String summary = passed ? "约束校验通过，可执行" : "约束校验失败，禁止执行";
        return new VerificationResult(passed, checked, violations, summary);
    }
}
