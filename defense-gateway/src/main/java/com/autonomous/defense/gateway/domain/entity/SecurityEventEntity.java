package com.autonomous.defense.gateway.domain.entity;

import com.autonomous.defense.gateway.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "security_events")
public class SecurityEventEntity extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", nullable = false, unique = true, length = 64)
    private String eventId;

    @Column(name = "event_timestamp", nullable = false)
    private Instant timestamp;

    @Column(name = "source_type", nullable = false, length = 64)
    private String sourceType;

    @Column(name = "subject_value", nullable = false, length = 512)
    private String subject;

    @Column(name = "action_value", nullable = false, length = 128)
    private String action;

    @Column(name = "object_value", nullable = false, length = 512)
    private String object;

    @Column(name = "context_json", nullable = false, columnDefinition = "TEXT")
    private String contextJson;

    @Column(name = "severity", nullable = false, length = 32)
    private String severity;

    @Column(name = "risk_score", nullable = false)
    private Double riskScore;

    @Column(name = "labels_json", nullable = false, columnDefinition = "TEXT")
    private String labelsJson;
}

