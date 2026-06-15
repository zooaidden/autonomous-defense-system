package com.autonomous.defense.actuator.adapter.impl;

import com.autonomous.defense.actuator.adapter.ActionAdapter;
import com.autonomous.defense.actuator.dto.DefenseStrategyRequest;
import com.autonomous.defense.actuator.exception.BusinessException;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

@Component
public class K8sAdapter implements ActionAdapter {

    // Kubernetes object names must follow RFC 1123 (lowercase alphanumerics
    // plus '-', max 63 chars). We tighten this to also forbid leading or
    // trailing dashes so the YAML we emit is never rejected by kubectl.
    private static final Pattern KUBE_NAME = Pattern.compile("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$");

    @Override
    public boolean supports(String actionType) {
        return "RESTRICT_EGRESS".equalsIgnoreCase(actionType) || "ISOLATE_POD".equalsIgnoreCase(actionType);
    }

    @Override
    public Map<String, Object> generateConfig(DefenseStrategyRequest.DefenseActionDTO action, DefenseStrategyRequest strategy) {
        // Defense in depth: even though StrategyExecutionService already
        // validates these fields, re-sanitise here so the YAML we emit is
        // never affected by future callers that forget the pre-check.
        String policyName = sanitiseForK8s("np-" + strategy.getStrategyId(), "strategyId");
        String appLabel = sanitiseForK8s(action.getTarget(), "action.target");
        String yaml = "apiVersion: networking.k8s.io/v1\n"
                + "kind: NetworkPolicy\n"
                + "metadata:\n"
                + "  name: " + policyName + "\n"
                + "spec:\n"
                + "  podSelector:\n"
                + "    matchLabels:\n"
                + "      app: " + appLabel + "\n"
                + "  policyTypes:\n"
                + "    - Egress\n";
        return Map.of(
                "adapter", "K8sAdapter",
                "format", "yaml",
                "content", yaml
        );
    }

    private static String sanitiseForK8s(String raw, String fieldName) {
        if (raw == null) {
            throw new BusinessException(fieldName + " must not be null");
        }
        String trimmed = raw.trim().toLowerCase(Locale.ROOT);
        // Reject if it contains anything outside the K8s allow-list. We do
        // not silently rewrite the value because a rewritten name no longer
        // matches the upstream strategy snapshot.
        if (!KUBE_NAME.matcher(trimmed).matches()) {
            throw new BusinessException(
                    fieldName + " must match RFC 1123 ([a-z0-9-]{1,63}, no leading/trailing dash); "
                            + "got: '" + truncate(raw, 80) + "'");
        }
        return trimmed;
    }

    private static String truncate(String s, int max) {
        return s == null ? "<null>" : (s.length() > max ? s.substring(0, max) + "..." : s);
    }
}

