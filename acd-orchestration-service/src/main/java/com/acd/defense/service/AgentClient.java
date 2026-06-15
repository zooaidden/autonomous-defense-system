package com.acd.defense.service;

import com.acd.defense.domain.DebateResponse;
import com.acd.defense.domain.SecurityEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;

@Service
public class AgentClient {
    private final WebClient webClient;

    public AgentClient(@Value("${agent.service.base-url}") String baseUrl) {
        this.webClient = WebClient.builder().baseUrl(baseUrl).build();
    }

    public DebateResponse debate(SecurityEvent event) {
        return webClient.post()
                .uri("/debate")
                .bodyValue(event)
                .retrieve()
                .bodyToMono(DebateResponse.class)
                .block();
    }

    /**
     * Subscribe to the agent-service SSE stream and emit each event's JSON
     * payload as a raw String (the `data:` part). Downstream code is
     * responsible for parsing it back into structured fields.
     */
    public Flux<String> debateStream(SecurityEvent event) {
        ParameterizedTypeReference<ServerSentEvent<String>> typeRef =
                new ParameterizedTypeReference<>() {};
        return webClient.post()
                .uri("/debate/stream")
                .accept(MediaType.TEXT_EVENT_STREAM)
                .bodyValue(event)
                .retrieve()
                .bodyToFlux(typeRef)
                .map(sse -> sse.data() == null ? "{}" : sse.data());
    }
}
