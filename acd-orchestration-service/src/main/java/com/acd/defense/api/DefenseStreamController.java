package com.acd.defense.api;

import com.acd.defense.domain.DebateState;
import com.acd.defense.domain.DefenseLoopResult;
import com.acd.defense.domain.DefenseStrategy;
import com.acd.defense.domain.ExecutionRecord;
import com.acd.defense.domain.SecurityEvent;
import com.acd.defense.domain.VerificationResult;
import com.acd.defense.service.AgentClient;
import com.acd.defense.service.DefenseOrchestratorService;
import com.acd.defense.service.ExecutionService;
import com.acd.defense.service.SimulatedEventLibrary;
import com.acd.defense.service.VerificationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@RestController
@RequestMapping("/api")
public class DefenseStreamController {

    private final DefenseOrchestratorService orchestratorService;
    private final AgentClient agentClient;
    private final VerificationService verificationService;
    private final ExecutionService executionService;
    private final SimulatedEventLibrary simulatedEventLibrary;
    private final ObjectMapper mapper;

    public DefenseStreamController(DefenseOrchestratorService orchestratorService,
                                   AgentClient agentClient,
                                   VerificationService verificationService,
                                   ExecutionService executionService,
                                   SimulatedEventLibrary simulatedEventLibrary,
                                   ObjectMapper mapper) {
        this.orchestratorService = orchestratorService;
        this.agentClient = agentClient;
        this.verificationService = verificationService;
        this.executionService = executionService;
        this.simulatedEventLibrary = simulatedEventLibrary;
        this.mapper = mapper;
    }

    @GetMapping(value = "/events/simulate/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<String>> simulateStream(
            @RequestParam(value = "scenario", required = false) String scenario) {

        SecurityEvent raw = (scenario == null || scenario.isBlank())
                ? simulatedEventLibrary.pickRandom()
                : simulatedEventLibrary.pickById(scenario);
        SecurityEvent normalized = orchestratorService.normalize(raw);

        AtomicReference<String> debateDoneJson = new AtomicReference<>();

        return Flux.<ServerSentEvent<String>>create(sink -> {
            sink.next(sse(payload("perception", Map.of("event", normalized))));

            agentClient.debateStream(normalized).subscribe(
                    data -> {
                        sink.next(sse(data));
                        try {
                            JsonNode node = mapper.readTree(data);
                            if ("debate_done".equals(node.path("type").asText())) {
                                debateDoneJson.set(data);
                            }
                        } catch (Exception ignore) {
                        }
                    },
                    err -> {
                        sink.next(sse(payload("agent_error", Map.of("error", err.toString()))));
                        sink.complete();
                    },
                    () -> {
                        try {
                            finalizeLoop(sink, normalized, debateDoneJson.get());
                        } catch (Exception e) {
                            sink.next(sse(payload("fatal_error", Map.of("error", e.toString()))));
                        } finally {
                            sink.complete();
                        }
                    }
            );
        });
    }

    private void finalizeLoop(reactor.core.publisher.FluxSink<ServerSentEvent<String>> sink,
                              SecurityEvent normalized,
                              String doneJson) throws Exception {
        if (doneJson == null) {
            return;
        }
        JsonNode done = mapper.readTree(doneJson);
        DebateState debateState = mapper.treeToValue(done.get("debateState"), DebateState.class);
        DefenseStrategy strategy = mapper.treeToValue(done.get("strategy"), DefenseStrategy.class);

        VerificationResult vr = verificationService.verify(normalized, strategy);
        sink.next(sse(payload("verify", Map.of("verificationResult", vr))));

        ExecutionRecord er = null;
        if (vr.passed()) {
            er = executionService.execute(strategy);
            sink.next(sse(payload("execute", Map.of("executionRecord", er))));
        }

        DefenseLoopResult loop = new DefenseLoopResult(normalized, debateState, strategy, vr, er);
        sink.next(sse(payload("final", Map.of("loop", loop))));
    }

    private String payload(String type, Map<String, Object> fields) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", type);
        body.putAll(fields);
        try {
            return mapper.writeValueAsString(body);
        } catch (Exception e) {
            return "{\"type\":\"" + type + "\",\"error\":\"serialize_failed\"}";
        }
    }

    private static ServerSentEvent<String> sse(String data) {
        return ServerSentEvent.<String>builder().data(data).build();
    }
}
