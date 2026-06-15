package com.autonomous.defense.gateway.dto;

import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
public class SecurityEventDTO {
    private String eventId;
    private Instant timestamp;

    @NotBlank
    private String sourceType;

    @NotBlank
    private String subject;

    @NotBlank
    private String action;

    @NotBlank
    private String object;

    private Map<String, Object> context;

    @NotBlank
    private String severity;

    @DecimalMin("0.0")
    @DecimalMax("1.0")
    private Double riskScore;

    @NotEmpty
    private List<String> labels;
}

