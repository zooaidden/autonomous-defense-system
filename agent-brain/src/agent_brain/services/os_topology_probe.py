from __future__ import annotations

import asyncio
import json
import os
import platform
import socket
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_brain.integrations.os_client import OsMCPClient


_REPO_ROOT = Path(__file__).resolve().parents[4]
_DEFAULT_DYNAMIC_TOPOLOGY_PATH = (
    _REPO_ROOT / "mcp-servers" / "topology-mcp-server" / "topology.dynamic.json"
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _split_host_port(value: str) -> tuple[str, int | None]:
    raw = str(value or "").strip()
    if not raw or raw in {"*", "*:*", "0.0.0.0:*", "[::]:*"}:
        return "", None
    if raw.startswith("[") and "]:" in raw:
        host, _, port = raw[1:].partition("]:")
        return host, _safe_int(port) if port.isdigit() else None
    if ":" not in raw:
        return raw, None
    host, port = raw.rsplit(":", 1)
    return host.strip("[]"), _safe_int(port) if port.isdigit() else None


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def _is_unspecified(host: str) -> bool:
    return host in {"", "*", "0.0.0.0", "::", "[::]"}


def _is_private(host: str) -> bool:
    return (
        host.startswith("10.")
        or host.startswith("192.168.")
        or any(host.startswith(f"172.{i}.") for i in range(16, 32))
        or _is_loopback(host)
    )


def _asset_id(prefix: str, value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in value.lower()).strip("-")
    return f"{prefix}-{cleaned[:72] or 'unknown'}"


def _upsert_asset(assets: dict[str, dict[str, Any]], asset: dict[str, Any]) -> None:
    aid = str(asset["asset_id"])
    existing = assets.get(aid)
    if existing is None:
        assets[aid] = asset
        return
    for key, value in asset.items():
        if key == "services" and isinstance(value, list):
            merged = list(existing.get("services") or [])
            for item in value:
                if item not in merged:
                    merged.append(item)
            existing["services"] = merged
        elif key == "tags" and isinstance(value, list):
            merged = set(existing.get("tags") or [])
            merged.update(value)
            existing["tags"] = sorted(merged)
        elif value and not existing.get(key):
            existing[key] = value


def _append_edge(edges: list[dict[str, Any]], edge: dict[str, Any]) -> None:
    key = (
        edge.get("from"),
        edge.get("to"),
        edge.get("protocol"),
        edge.get("port"),
        edge.get("direction"),
    )
    for existing in edges:
        if (
            existing.get("from"),
            existing.get("to"),
            existing.get("protocol"),
            existing.get("port"),
            existing.get("direction"),
        ) == key:
            existing["observed_count"] = _safe_int(existing.get("observed_count"), 1) + 1
            return
    edge.setdefault("allowed", True)
    edge.setdefault("observed_count", 1)
    edges.append(edge)


def build_dynamic_topology(
    *,
    sockets_envelope: dict[str, Any],
    processes_envelope: dict[str, Any],
    generated_by: str,
) -> dict[str, Any]:
    """Convert OS socket/process snapshots into topology + knowledge graph."""
    host = socket.gethostname()
    machine = platform.machine()
    generated_at = _now_iso()
    host_asset_id = _asset_id("host", host)

    assets: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    kg_nodes: dict[str, dict[str, Any]] = {}
    kg_edges: list[dict[str, Any]] = []

    _upsert_asset(
        assets,
        {
            "asset_id": host_asset_id,
            "name": host,
            "ip": "local",
            "zone": "LocalHost",
            "role": "observed-host",
            "criticality": "HIGH",
            "services": [],
            "tags": ["dynamic", "os-probed", machine],
        },
    )
    kg_nodes[host_asset_id] = {
        "id": host_asset_id,
        "label": host,
        "type": "host",
        "properties": {"machine": machine},
    }

    process_result = processes_envelope.get("result")
    process_rows = (
        process_result.get("processes")
        if isinstance(process_result, dict)
        else process_result
    ) or []
    process_by_comm: dict[str, dict[str, Any]] = {}
    if isinstance(process_rows, list):
        for proc in process_rows:
            if not isinstance(proc, dict):
                continue
            comm = str(proc.get("comm") or proc.get("command") or "").strip()
            if comm and comm not in process_by_comm:
                process_by_comm[comm] = proc

    socket_rows = ((sockets_envelope.get("result") or {}).get("sockets")) or []
    if not isinstance(socket_rows, list):
        socket_rows = []

    for row in socket_rows:
        if not isinstance(row, dict):
            continue
        proto = str(row.get("protocol") or "").upper()
        state = str(row.get("state") or "")
        local_host, local_port = _split_host_port(str(row.get("local_address") or ""))
        peer_host, peer_port = _split_host_port(str(row.get("peer_address") or ""))
        process_raw = str(row.get("process") or "")
        process_name = process_raw.split(",", 1)[0].replace('users:(("', "").strip('"()') or "unknown"

        local_service_id = _asset_id("svc", f"{host}-{local_port or 'any'}-{process_name}")
        _upsert_asset(
            assets,
            {
                "asset_id": local_service_id,
                "name": process_name,
                "ip": local_host or "0.0.0.0",
                "zone": "LocalHost",
                "role": "listening-service" if state.upper() == "LISTEN" else "local-process",
                "criticality": "MEDIUM",
                "services": [f"{proto}/{local_port}"] if local_port else [proto],
                "tags": ["dynamic", "os-socket", state.lower()],
            },
        )
        kg_nodes[local_service_id] = {
            "id": local_service_id,
            "label": process_name,
            "type": "service",
            "properties": {
                "local_address": row.get("local_address"),
                "process": process_raw,
                "state": state,
            },
        }
        _append_edge(
            edges,
            {
                "from": host_asset_id,
                "to": local_service_id,
                "protocol": proto,
                "port": local_port,
                "direction": "outbound",
                "allowed": True,
                "state": state,
                "source": "os_socket",
            },
        )
        kg_edges.append(
            {
                "source": host_asset_id,
                "target": local_service_id,
                "type": "RUNS",
                "properties": {"state": state},
            }
        )

        if _is_unspecified(peer_host):
            continue
        zone = "Loopback" if _is_loopback(peer_host) else "PrivateNetwork" if _is_private(peer_host) else "ExternalNetwork"
        remote_id = _asset_id("peer", peer_host)
        _upsert_asset(
            assets,
            {
                "asset_id": remote_id,
                "name": peer_host,
                "ip": peer_host,
                "zone": zone,
                "role": "network-peer",
                "criticality": "MEDIUM" if zone == "PrivateNetwork" else "LOW",
                "services": [f"{proto}/{peer_port}"] if peer_port else [proto],
                "tags": ["dynamic", "os-peer", zone.lower()],
            },
        )
        kg_nodes[remote_id] = {
            "id": remote_id,
            "label": peer_host,
            "type": "network_peer",
            "properties": {"zone": zone},
        }
        _append_edge(
            edges,
            {
                "from": local_service_id,
                "to": remote_id,
                "protocol": proto,
                "port": peer_port or local_port,
                "direction": "outbound",
                "allowed": True,
                "state": state,
                "source": "os_socket",
            },
        )
        kg_edges.append(
            {
                "source": local_service_id,
                "target": remote_id,
                "type": "CONNECTS_TO",
                "properties": {"protocol": proto, "state": state, "port": peer_port or local_port},
            }
        )

    return {
        "metadata": {
            "source": "os_probe",
            "dynamic": True,
            "generatedAt": generated_at,
            "generatedBy": generated_by,
            "host": host,
            "machine": machine,
            "socketCount": len(socket_rows),
            "processSampleCount": len(process_by_comm),
        },
        "zones": [
            {"id": "LocalHost", "label": "Local host observed by OS probe"},
            {"id": "Loopback", "label": "Loopback peers"},
            {"id": "PrivateNetwork", "label": "Private network peers"},
            {"id": "ExternalNetwork", "label": "External network peers"},
        ],
        "assets": list(assets.values()),
        "edges": edges,
        "knowledge_graph": {
            "nodes": list(kg_nodes.values()),
            "edges": kg_edges,
        },
        "raw_probe": {
            "sockets": sockets_envelope,
            "processes": processes_envelope,
        },
    }


class OsTopologyProbeManager:
    """Manual and optional automatic OS topology probe coordinator."""

    def __init__(
        self,
        *,
        dynamic_topology_path: str | os.PathLike[str] | None = None,
        auto_enabled: bool | None = None,
        interval_seconds: int | None = None,
    ) -> None:
        path = dynamic_topology_path or os.environ.get("DYNAMIC_TOPOLOGY_PATH")
        self.dynamic_topology_path = (
            Path(path).expanduser().resolve() if path else _DEFAULT_DYNAMIC_TOPOLOGY_PATH
        )
        self.auto_enabled = (
            _env_bool("ENABLE_OS_TOPOLOGY_AUTO_PROBE", False)
            if auto_enabled is None
            else bool(auto_enabled)
        )
        self.interval_seconds = (
            int(os.environ.get("OS_TOPOLOGY_AUTO_PROBE_INTERVAL_SECONDS", "86400"))
            if interval_seconds is None
            else int(interval_seconds)
        )
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._status: dict[str, Any] = {
            "manualEnabled": True,
            "autoEnabled": self.auto_enabled,
            "intervalSeconds": self.interval_seconds,
            "running": False,
            "lastProbeAt": None,
            "lastProbeMode": None,
            "lastError": None,
            "dynamicTopologyPath": str(self.dynamic_topology_path),
            "assetCount": 0,
            "edgeCount": 0,
            "knowledgeNodeCount": 0,
            "knowledgeEdgeCount": 0,
        }

    def start_auto(self) -> None:
        if not self.auto_enabled or self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._auto_loop,
            name="os-topology-auto-probe",
            daemon=True,
        )
        self._thread.start()

    def stop_auto(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        with self._lock:
            self._status["running"] = False

    def status(self) -> dict[str, Any]:
        stored = self.load_stored_topology()
        with self._lock:
            out = dict(self._status)
        if stored:
            out["assetCount"] = len(stored.get("assets") or [])
            out["edgeCount"] = len(stored.get("edges") or [])
            kg = stored.get("knowledge_graph") or {}
            out["knowledgeNodeCount"] = len(kg.get("nodes") or [])
            out["knowledgeEdgeCount"] = len(kg.get("edges") or [])
            out["lastProbeAt"] = (stored.get("metadata") or {}).get("generatedAt") or out["lastProbeAt"]
        return out

    def load_stored_topology(self) -> dict[str, Any] | None:
        try:
            if not self.dynamic_topology_path.is_file():
                return None
            return json.loads(self.dynamic_topology_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    async def probe(self, *, mode: str = "manual") -> dict[str, Any]:
        with self._lock:
            if self._status["running"]:
                already_running = True
            else:
                already_running = False
                self._status["running"] = True
                self._status["lastProbeMode"] = mode
                self._status["lastError"] = None
        if already_running:
            return {
                "success": False,
                "message": "OS topology probe is already running",
                "data": self.status(),
            }
        try:
            async with OsMCPClient() as client:
                sockets = await client.get_network_sockets(top_n=1000)
                processes = await client.get_process_list(top_n=200)
            topology = build_dynamic_topology(
                sockets_envelope=sockets,
                processes_envelope=processes,
                generated_by=mode,
            )
            self._write_topology(topology)
            with self._lock:
                self._status.update(
                    {
                        "running": False,
                        "lastProbeAt": topology["metadata"]["generatedAt"],
                        "lastProbeMode": mode,
                        "lastError": None,
                        "assetCount": len(topology.get("assets") or []),
                        "edgeCount": len(topology.get("edges") or []),
                        "knowledgeNodeCount": len((topology.get("knowledge_graph") or {}).get("nodes") or []),
                        "knowledgeEdgeCount": len((topology.get("knowledge_graph") or {}).get("edges") or []),
                    }
                )
            return {
                "success": True,
                "message": "OS topology probe completed",
                "data": {
                    "status": self.status(),
                    "topology": topology,
                    "knowledgeGraph": topology.get("knowledge_graph") or {},
                },
            }
        except Exception as exc:
            with self._lock:
                self._status["running"] = False
                self._status["lastError"] = f"{exc.__class__.__name__}: {exc}"
            return {"success": False, "message": str(exc), "data": {"status": self.status()}}

    def _write_topology(self, topology: dict[str, Any]) -> None:
        self.dynamic_topology_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.dynamic_topology_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(topology, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.dynamic_topology_path)

    def _auto_loop(self) -> None:
        while not self._stop.is_set():
            stored = self.load_stored_topology()
            if stored is None:
                asyncio.run(self.probe(mode="auto-missing"))
            if self._stop.wait(self.interval_seconds):
                break
            asyncio.run(self.probe(mode="auto-interval"))
