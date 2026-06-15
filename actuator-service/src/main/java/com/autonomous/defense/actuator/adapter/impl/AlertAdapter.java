package com.autonomous.defense.actuator.adapter.impl;

import com.autonomous.defense.actuator.adapter.ActionAdapter;
import com.autonomous.defense.actuator.dto.DefenseStrategyRequest;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Audit-only handler for ALERT_ONLY. Does not apply K8s, WAF, or firewall changes.
 */
@Component
public class AlertAdapter implements ActionAdapter {

    private static final String EFFECT_NO_RUNTIME_CHANGE = "NO_RUNTIME_CHANGE";

    /** Fixed audit message returned for every ALERT_ONLY execution. */
    public static final String DEFAULT_ALERT_MESSAGE = "Alert-only action recorded for audit.";

    @Override
    public boolean supports(String actionType) {
        return "ALERT_ONLY".equalsIgnoreCase(actionType);
    }

    /**
     * Builds an audit artifact with kind ALERT_ONLY and {@link #EFFECT_NO_RUNTIME_CHANGE}.
     *
     * @param params optional; {@code reason} may be read from {@code parameters.reason}
     */
    public static Map<String, Object> buildArtifact(
            DefenseStrategyRequest.DefenseActionDTO action,
            Map<String, Object> params
    ) {
        Map<String, Object> artifact = new LinkedHashMap<>();
        artifact.put("kind", "ALERT_ONLY");
        artifact.put("target", action.getTarget());
        artifact.put("effect", EFFECT_NO_RUNTIME_CHANGE);
        artifact.put("message", DEFAULT_ALERT_MESSAGE);
        Object reason = params != null ? params.get("reason") : null;
        artifact.put("reason", reason);
        return artifact;
    }

    @Override
    public Map<String, Object> generateConfig(DefenseStrategyRequest.DefenseActionDTO action, DefenseStrategyRequest strategy) {
        Objects.requireNonNull(strategy, "strategy");
        return buildArtifact(action, action.getParameters());
    }
}
