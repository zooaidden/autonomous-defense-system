package com.acd.defense.domain;

import java.util.List;
import java.util.Map;

public record DebateState(
        String roundId,
        List<String> plannerIdeas,
        List<String> redTeamChallenges,
        Map<String, Object> coordinatorDecision
) {
}
