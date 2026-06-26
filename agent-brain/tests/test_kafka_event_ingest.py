import json

from agent_brain.integrations.kafka_consumer import security_event_from_kafka_value


def test_security_event_from_kafka_value_parses_gateway_payload():
    payload = {
        "eventId": "evt-real-001",
        "timestamp": "2026-06-26T08:00:00Z",
        "sourceType": "SIEM",
        "subject": "host/web-01",
        "action": "network_connection",
        "object": "203.0.113.10:443",
        "context": {"srcIp": "10.0.1.12"},
        "severity": "HIGH",
        "riskScore": 0.86,
        "labels": ["real-feed"],
    }

    event = security_event_from_kafka_value(json.dumps(payload))

    assert event.eventId == "evt-real-001"
    assert event.sourceType == "SIEM"
    assert event.severity == "HIGH"
    assert event.context["srcIp"] == "10.0.1.12"
