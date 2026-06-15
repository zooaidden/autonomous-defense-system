from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BusinessDependencySnapshot:
    service_dependencies: dict[str, list[str]]
    protected_services: set[str]
    public_entry_services: set[str]
    db_allowlist: dict[str, set[str]]
    core_services_in_prod: set[str]


class MockDependencyProvider:
    """Mock 资产依赖图提供器，后续可替换为 CMDB/GraphDB 实现。"""

    def get_snapshot(self) -> BusinessDependencySnapshot:
        return BusinessDependencySnapshot(
            service_dependencies={
                "payment-service": ["auth-service", "redis-auth"],
            },
            protected_services={"core-dns"},
            public_entry_services={"gateway-service"},
            db_allowlist={
                "db-primary": {"payment-service", "auth-service"},
            },
            core_services_in_prod={"payment-service", "auth-service", "gateway-service", "core-dns"},
        )

