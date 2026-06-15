package com.acd.defense.domain;

public record DebateResponse(
        DebateState debateState,
        DefenseStrategy strategy
) {
}
