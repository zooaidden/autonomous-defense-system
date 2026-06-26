from __future__ import annotations

from collections.abc import Iterator
import json
import logging
import threading
from datetime import UTC, datetime
from typing import Any

from kafka import KafkaConsumer

from agent_brain.models import SecurityEvent

logger = logging.getLogger(__name__)


class SecurityEventKafkaConsumer:
    """Kafka 消费器封装，用于从真实事件总线感知安全事件。"""

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        group_id: str = "agent-brain",
        *,
        auto_offset_reset: str = "latest",
    ) -> None:
        self._consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            auto_offset_reset=auto_offset_reset,
            value_deserializer=lambda v: v.decode("utf-8"),
            enable_auto_commit=True,
        )

    def stream(self) -> Iterator[Any]:
        for msg in self._consumer:
            yield msg.value

    def close(self) -> None:
        self._consumer.close()


class SecurityEventIngestWorker:
    """Background Kafka worker that feeds real events into agent-brain.

    The worker is deliberately small and optional. It gives the system real
    event awareness without changing the existing dashboard Sandbox flow or the
    manual ``POST /workflow/run`` API.
    """

    def __init__(
        self,
        *,
        enabled: bool,
        bootstrap_servers: str,
        topic: str,
        group_id: str,
        event_handler,
        auto_offset_reset: str = "latest",
    ) -> None:
        self.enabled = enabled
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.group_id = group_id
        self.auto_offset_reset = auto_offset_reset
        self._event_handler = event_handler
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._consumer: SecurityEventKafkaConsumer | None = None
        self._lock = threading.Lock()
        self._status: dict[str, Any] = {
            "enabled": enabled,
            "running": False,
            "topic": topic,
            "bootstrapServers": bootstrap_servers,
            "groupId": group_id,
            "autoOffsetReset": auto_offset_reset,
            "processedCount": 0,
            "failedCount": 0,
            "lastEventId": None,
            "lastProcessedAt": None,
            "lastError": None,
        }

    def start(self) -> None:
        if not self.enabled or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="security-event-kafka-ingest",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._consumer is not None:
            self._consumer.close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        with self._lock:
            self._status["running"] = False

    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._status)

    def _run(self) -> None:
        with self._lock:
            self._status["running"] = True
            self._status["lastError"] = None
        try:
            self._consumer = SecurityEventKafkaConsumer(
                self.bootstrap_servers,
                self.topic,
                self.group_id,
                auto_offset_reset=self.auto_offset_reset,
            )
            for raw in self._consumer.stream():
                if self._stop.is_set():
                    break
                self._handle_raw(raw)
        except Exception as exc:  # pragma: no cover - depends on live Kafka
            logger.exception("security event Kafka ingest worker stopped")
            with self._lock:
                self._status["running"] = False
                self._status["lastError"] = str(exc)
        finally:
            with self._lock:
                self._status["running"] = False

    def _handle_raw(self, raw: Any) -> None:
        try:
            event = security_event_from_kafka_value(raw)
            self._event_handler(event)
        except Exception as exc:
            logger.warning("failed to process Kafka security event: %s", exc)
            with self._lock:
                self._status["failedCount"] += 1
                self._status["lastError"] = str(exc)
            return
        with self._lock:
            self._status["processedCount"] += 1
            self._status["lastEventId"] = event.eventId
            self._status["lastProcessedAt"] = datetime.now(UTC).isoformat()
            self._status["lastError"] = None


def security_event_from_kafka_value(raw: Any) -> SecurityEvent:
    """Parse a defense-gateway Kafka payload into the agent-brain schema."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        payload = json.loads(raw)
    elif isinstance(raw, dict):
        payload = raw
    else:
        raise TypeError(f"unsupported Kafka value type: {type(raw).__name__}")
    return SecurityEvent.model_validate(payload)

