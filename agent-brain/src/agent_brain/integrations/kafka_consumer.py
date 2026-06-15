from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from kafka import KafkaConsumer


class SecurityEventKafkaConsumer:
    """Kafka 消费器封装。当前用于本地开发骨架，支持后续接入真实流式处理。"""

    def __init__(self, bootstrap_servers: str, topic: str, group_id: str = "agent-brain") -> None:
        self._consumer = KafkaConsumer(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            auto_offset_reset="earliest",
            value_deserializer=lambda v: v.decode("utf-8"),
            enable_auto_commit=True,
        )

    def stream(self) -> Iterator[Any]:
        for msg in self._consumer:
            yield msg.value

