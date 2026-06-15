package com.autonomous.defense.actuator.repository;

import com.autonomous.defense.actuator.model.ExecutionRecord;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Repository
public class ExecutionRecordRepository {
    private final Map<String, ExecutionRecord> storage = new ConcurrentHashMap<>();

    public ExecutionRecord save(ExecutionRecord record) {
        storage.put(record.executionId(), record);
        return record;
    }

    public Optional<ExecutionRecord> findById(String executionId) {
        return Optional.ofNullable(storage.get(executionId));
    }

    public List<ExecutionRecord> findAll() {
        List<ExecutionRecord> records = new ArrayList<>(storage.values());
        records.sort(Comparator.comparing(ExecutionRecord::startTime).reversed());
        return records;
    }

    public List<ExecutionRecord> findAutoRollbackCandidates(long nowEpochSeconds) {
        List<ExecutionRecord> all = findAll();
        List<ExecutionRecord> candidates = new ArrayList<>();
        for (ExecutionRecord r : all) {
            if (r.ttl() == null || r.ttl() <= 0) {
                continue;
            }
            if (r.rollbackStatus() != com.autonomous.defense.actuator.model.RollbackStatus.AVAILABLE) {
                continue;
            }
            long dueAt = r.startTime().getEpochSecond() + r.ttl();
            if (nowEpochSeconds >= dueAt) {
                candidates.add(r);
            }
        }
        return candidates;
    }

    public Set<String> existingExecutionIds() {
        return new HashSet<>(storage.keySet());
    }
}

