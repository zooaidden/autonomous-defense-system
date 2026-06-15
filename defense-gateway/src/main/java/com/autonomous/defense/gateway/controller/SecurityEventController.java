package com.autonomous.defense.gateway.controller;

import com.autonomous.defense.gateway.common.ApiResponse;
import com.autonomous.defense.gateway.common.PageResponse;
import com.autonomous.defense.gateway.dto.SecurityEventDTO;
import com.autonomous.defense.gateway.dto.SecurityEventQuery;
import com.autonomous.defense.gateway.service.SecurityEventService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/events")
@RequiredArgsConstructor
public class SecurityEventController {

    private final SecurityEventService securityEventService;

    @PostMapping
    public ResponseEntity<ApiResponse<SecurityEventDTO>> create(@Valid @RequestBody SecurityEventDTO request) {
        log.info("Create security event request. sourceType={}, severity={}", request.getSourceType(), request.getSeverity());
        SecurityEventDTO created = securityEventService.createEvent(request);
        return ResponseEntity.ok(ApiResponse.created(created));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<PageResponse<SecurityEventDTO>>> list(@Valid SecurityEventQuery query) {
        PageRequest pageable = PageRequest.of(query.getPage(), query.getSize(), Sort.by(Sort.Direction.DESC, "timestamp"));
        Page<SecurityEventDTO> page = securityEventService.listEvents(pageable);
        return ResponseEntity.ok(ApiResponse.ok(PageResponse.of(page)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<SecurityEventDTO>> detail(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(securityEventService.getEventById(id)));
    }

    // Lookup by string eventId for clients that only carry the high-level
    // identifier (dashboard-ui falls back to this route when /events/{numericId} 404s).
    @GetMapping("/by-event-id/{eventId}")
    public ResponseEntity<ApiResponse<SecurityEventDTO>> detailByEventId(@PathVariable String eventId) {
        return ResponseEntity.ok(ApiResponse.ok(securityEventService.getEventByEventId(eventId)));
    }

    @PostMapping("/mock/log4j")
    public ResponseEntity<ApiResponse<SecurityEventDTO>> mockLog4j() {
        log.info("Generate mock log4j attack event");
        return ResponseEntity.ok(ApiResponse.created(securityEventService.createMockLog4jEvent()));
    }

    @PostMapping("/mock/shell")
    public ResponseEntity<ApiResponse<SecurityEventDTO>> mockShell() {
        log.info("Generate mock container shell event");
        return ResponseEntity.ok(ApiResponse.created(securityEventService.createMockShellEvent()));
    }
}

