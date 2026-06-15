package com.acd.defense.api;

import com.acd.defense.domain.DefenseLoopResult;
import com.acd.defense.domain.ExecutionRecord;
import com.acd.defense.domain.SecurityEvent;
import com.acd.defense.service.DefenseOrchestratorService;
import com.acd.defense.service.ExecutionService;
import com.acd.defense.service.SimulatedEventLibrary;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class DefenseController {
    private final DefenseOrchestratorService orchestratorService;
    private final ExecutionService executionService;
    private final SimulatedEventLibrary simulatedEventLibrary;

    public DefenseController(DefenseOrchestratorService orchestratorService,
                             ExecutionService executionService,
                             SimulatedEventLibrary simulatedEventLibrary) {
        this.orchestratorService = orchestratorService;
        this.executionService = executionService;
        this.simulatedEventLibrary = simulatedEventLibrary;
    }

    @PostMapping("/events")
    public DefenseLoopResult submitEvent(@Valid @RequestBody SecurityEvent event) {
        return orchestratorService.runLoop(event);
    }

    @PostMapping("/events/simulate")
    public DefenseLoopResult simulate(@RequestParam(value = "scenario", required = false) String scenario) {
        SecurityEvent event = (scenario == null || scenario.isBlank())
                ? simulatedEventLibrary.pickRandom()
                : simulatedEventLibrary.pickById(scenario);
        return orchestratorService.runLoop(event);
    }

    @GetMapping("/events/scenarios")
    public List<SimulatedEventLibrary.ScenarioMeta> listScenarios() {
        return simulatedEventLibrary.listScenarios();
    }

    @GetMapping("/audit/records")
    public List<ExecutionRecord> listAuditRecords() {
        return executionService.listRecords();
    }
}
