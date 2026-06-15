package com.autonomous.defense.actuator.adapter;

import com.autonomous.defense.actuator.dto.DefenseStrategyRequest;

import java.util.Map;

public interface ActionAdapter {
    boolean supports(String actionType);

    Map<String, Object> generateConfig(DefenseStrategyRequest.DefenseActionDTO action, DefenseStrategyRequest strategy);
}

