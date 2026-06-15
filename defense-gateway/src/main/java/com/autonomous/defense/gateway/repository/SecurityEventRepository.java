package com.autonomous.defense.gateway.repository;

import com.autonomous.defense.gateway.domain.entity.SecurityEventEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SecurityEventRepository extends JpaRepository<SecurityEventEntity, Long> {
    Optional<SecurityEventEntity> findByEventId(String eventId);
}

