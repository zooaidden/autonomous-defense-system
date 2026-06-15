package com.autonomous.defense.gateway.service;

import com.autonomous.defense.gateway.dto.SecurityEventDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface SecurityEventService {
    SecurityEventDTO createEvent(SecurityEventDTO request);

    Page<SecurityEventDTO> listEvents(Pageable pageable);

    SecurityEventDTO getEventById(Long id);

    SecurityEventDTO getEventByEventId(String eventId);

    SecurityEventDTO createMockLog4jEvent();

    SecurityEventDTO createMockShellEvent();
}

