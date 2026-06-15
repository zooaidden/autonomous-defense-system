package com.autonomous.defense.actuator.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class DefenseStrategyRequest {
    @NotBlank
    private String strategyId;

    @NotBlank
    private String threatType;

    @NotBlank
    private String targetLayer;

    @Valid
    @NotEmpty
    private List<DefenseActionDTO> actions;

    @Valid
    private ScopeDTO scope = new ScopeDTO();

    private Long ttl;

    @Valid
    private RollbackPlanDTO rollbackPlan;

    // When null or true the strategy is executed in dry-run mode and never
    // reaches the underlying adapters' real apply path. Only callers that
    // explicitly opt-in to real-run by sending dryRun=false will skip the
    // dry-run envelope. This keeps the actuator-service safe-by-default.
    private Boolean dryRun;

    @Data
    public static class DefenseActionDTO {
        @NotBlank
        private String type;

        @NotBlank
        private String target;

        private Map<String, Object> parameters;
    }

    @Data
    public static class ScopeDTO {
        private List<String> assets;
        private List<String> namespaces;
        private String tenantId;
    }

    @Data
    public static class RollbackPlanDTO {
        @NotBlank
        private String planId;
        private List<String> steps;
        private String triggerCondition;
    }
}

