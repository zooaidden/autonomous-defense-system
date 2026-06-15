package com.autonomous.defense.gateway.mapper;

import com.autonomous.defense.gateway.domain.entity.SecurityEventEntity;
import com.autonomous.defense.gateway.dto.SecurityEventDTO;
import com.autonomous.defense.gateway.exception.BusinessException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class SecurityEventMapper {

    private final ObjectMapper objectMapper;

    public SecurityEventEntity toEntity(SecurityEventDTO dto) {
        SecurityEventEntity entity = new SecurityEventEntity();
        entity.setEventId(dto.getEventId());
        entity.setTimestamp(dto.getTimestamp());
        entity.setSourceType(dto.getSourceType());
        entity.setSubject(dto.getSubject());
        entity.setAction(dto.getAction());
        entity.setObject(dto.getObject());
        entity.setSeverity(dto.getSeverity());
        entity.setRiskScore(dto.getRiskScore());
        entity.setContextJson(writeJson(dto.getContext()));
        entity.setLabelsJson(writeJson(dto.getLabels()));
        return entity;
    }

    public SecurityEventDTO toDto(SecurityEventEntity entity) {
        SecurityEventDTO dto = new SecurityEventDTO();
        dto.setEventId(entity.getEventId());
        dto.setTimestamp(entity.getTimestamp());
        dto.setSourceType(entity.getSourceType());
        dto.setSubject(entity.getSubject());
        dto.setAction(entity.getAction());
        dto.setObject(entity.getObject());
        dto.setSeverity(entity.getSeverity());
        dto.setRiskScore(entity.getRiskScore());
        dto.setContext(readMap(entity.getContextJson()));
        dto.setLabels(readList(entity.getLabelsJson()));
        return dto;
    }

    private String writeJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj == null ? Collections.emptyMap() : obj);
        } catch (JsonProcessingException e) {
            throw new BusinessException("Failed to serialize event payload");
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> readMap(String json) {
        try {
            return objectMapper.readValue(json, Map.class);
        } catch (JsonProcessingException e) {
            throw new BusinessException("Failed to deserialize context payload");
        }
    }

    @SuppressWarnings("unchecked")
    private List<String> readList(String json) {
        try {
            return objectMapper.readValue(json, List.class);
        } catch (JsonProcessingException e) {
            throw new BusinessException("Failed to deserialize labels payload");
        }
    }
}

