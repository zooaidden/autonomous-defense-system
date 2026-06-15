package com.acd.defense.service;

import com.acd.defense.domain.DefenseStrategy;
import com.acd.defense.domain.ExecutionRecord;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class ExecutionService {
    private final List<ExecutionRecord> records = new CopyOnWriteArrayList<>();

    public ExecutionRecord execute(DefenseStrategy strategy) {
        ExecutionRecord record = new ExecutionRecord(
                UUID.randomUUID().toString(),
                strategy.strategyId(),
                strategy.strategyType(),
                strategy.actions(),
                "APPLIED",
                Instant.now(),
                "rollback-" + strategy.strategyId()
        );
        records.add(0, record);
        return record;
    }

    public List<ExecutionRecord> listRecords() {
        return records;
    }
}
