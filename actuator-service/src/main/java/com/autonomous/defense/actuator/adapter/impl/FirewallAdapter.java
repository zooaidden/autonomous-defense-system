package com.autonomous.defense.actuator.adapter.impl;

import com.autonomous.defense.actuator.adapter.ActionAdapter;
import com.autonomous.defense.actuator.dto.DefenseStrategyRequest;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class FirewallAdapter implements ActionAdapter {
    @Override
    public boolean supports(String actionType) {
        return "BLOCK_IP".equalsIgnoreCase(actionType);
    }

    @Override
    public Map<String, Object> generateConfig(DefenseStrategyRequest.DefenseActionDTO action, DefenseStrategyRequest strategy) {
        return Map.of(
                "adapter", "FirewallAdapter",
                "format", "json",
                "content", Map.of(
                        "ruleType", "firewall",
                        "action", "deny",
                        "ip", action.getTarget(),
                        "strategyId", strategy.getStrategyId()
                )
        );
    }
}

