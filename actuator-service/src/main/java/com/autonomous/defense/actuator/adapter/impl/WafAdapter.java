package com.autonomous.defense.actuator.adapter.impl;

import com.autonomous.defense.actuator.adapter.ActionAdapter;
import com.autonomous.defense.actuator.dto.DefenseStrategyRequest;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class WafAdapter implements ActionAdapter {
    @Override
    public boolean supports(String actionType) {
        return "APPLY_WAF_RULE".equalsIgnoreCase(actionType);
    }

    @Override
    public Map<String, Object> generateConfig(DefenseStrategyRequest.DefenseActionDTO action, DefenseStrategyRequest strategy) {
        return Map.of(
                "adapter", "WafAdapter",
                "format", "json",
                "content", Map.of(
                        "ruleType", "waf",
                        "targetPath", action.getTarget(),
                        "mode", "block",
                        "signature", action.getParameters() == null ? "generic" : action.getParameters().getOrDefault("signature", "generic"),
                        "strategyId", strategy.getStrategyId()
                )
        );
    }
}

