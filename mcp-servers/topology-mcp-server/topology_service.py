"""Pure-Python topology service.

This module contains all topology business logic and is intentionally free
of any MCP / FastMCP imports. ``server.py`` wraps each public function as
an MCP tool or resource; tests import this module directly.

Public surface (module-level functions):
    - load_topology(path=None)
    - get_topology(topology=None)
    - find_asset(key, topology=None)
    - get_neighbors(key, topology=None)
    - get_critical_assets(topology=None)
    - find_paths(source, target, max_depth=4, topology=None)
    - check_connectivity(source, target, topology=None)
    - evaluate_strategy_impact(strategy, topology=None)

The ``topology`` parameter is optional everywhere. When omitted, the
default topology bundled with this server (``topology.json`` next to this
file) is loaded lazily and reused. Tests can pass a custom topology dict
to exercise the service in isolation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

DEFAULT_TOPOLOGY_PATH: Path = Path(__file__).parent / "topology.json"

# Hard cap on enumerated paths to prevent combinatorial explosion in dense
# graphs. Returned result advertises ``truncated=True`` when the cap is hit.
PATH_LIMIT: int = 50

# Action type buckets used for impact analysis.
DISRUPTIVE_ACTIONS = frozenset({"ISOLATE_POD", "ISOLATE_HOST"})
PARTIAL_ACTIONS = frozenset({"RESTRICT_EGRESS"})
NETWORK_BLOCK_ACTIONS = frozenset({"BLOCK_IP", "BLOCK_DOMAIN"})
PROTECTIVE_ACTIONS = frozenset({"APPLY_WAF_RULE", "APPLY_FIREWALL_RULE", "SCALE_PROTECTION"})
IDENTITY_ACTIONS = frozenset({"DISABLE_ACCOUNT", "REVOKE_TOKEN"})
PASSIVE_ACTIONS = frozenset({"ALERT_ONLY"})

# Effects that actually break network paths (used by the path-disruption
# detector inside ``evaluate_strategy_impact``).
DISRUPTING_EFFECTS = frozenset({"disruptive", "partial_disruptive", "network_block"})

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TopologyError(Exception):
    """Base class for topology service errors."""


class AssetNotFoundError(TopologyError):
    """Raised when an asset cannot be resolved by asset_id / ip / name."""

    def __init__(self, key: str):
        super().__init__(f"asset not found: {key}")
        self.key = key


# ---------------------------------------------------------------------------
# Internal state: lazy default topology + per-topology adjacency cache.
# ---------------------------------------------------------------------------

_default_topology: Optional[dict[str, Any]] = None
_adjacency_cache: dict[int, dict[str, list[tuple[str, dict[str, Any]]]]] = {}


def _resolve_topology(topology: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return ``topology`` if given, otherwise the lazily-loaded default."""
    global _default_topology
    if topology is not None:
        return topology
    if _default_topology is None:
        _default_topology = load_topology()
    return _default_topology


def _get_adjacency(
    topology: dict[str, Any],
) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """Memoize adjacency by topology object identity."""
    cache_key = id(topology)
    cached = _adjacency_cache.get(cache_key)
    if cached is None:
        cached = _build_adjacency(topology)
        _adjacency_cache[cache_key] = cached
    return cached


def _build_adjacency(
    topology: dict[str, Any],
) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    """Build a directed adjacency list from ``topology['edges']``.

    Only edges with ``allowed=True`` are considered. ``direction`` semantics:
        outbound      -> from -> to
        inbound       -> to -> from
        bidirectional -> both directions
    """
    assets = topology.get("assets") or []
    adj: dict[str, list[tuple[str, dict[str, Any]]]] = {
        a.get("asset_id"): [] for a in assets if a.get("asset_id")
    }
    for edge in topology.get("edges") or []:
        if not edge.get("allowed", True):
            continue
        src = edge.get("from")
        dst = edge.get("to")
        if not src or not dst:
            continue
        direction = (edge.get("direction") or "bidirectional").lower()
        if direction in ("outbound", "bidirectional", "both"):
            adj.setdefault(src, []).append((dst, edge))
        if direction in ("inbound", "bidirectional", "both"):
            adj.setdefault(dst, []).append((src, edge))
    return adj


def _edge_repr(edge: dict[str, Any]) -> dict[str, Any]:
    """Project an edge to a stable, JSON-serializable shape."""
    return {
        "from": edge.get("from"),
        "to": edge.get("to"),
        "protocol": edge.get("protocol"),
        "port": edge.get("port"),
        "direction": edge.get("direction", "bidirectional"),
        "allowed": edge.get("allowed", True),
    }


def _dfs_paths(
    topology: dict[str, Any],
    src: str,
    tgt: str,
    max_depth: int,
) -> list[dict[str, Any]]:
    """Enumerate simple paths from ``src`` to ``tgt`` up to ``max_depth`` hops."""
    if max_depth < 1 or src == tgt:
        return []
    adjacency = _get_adjacency(topology)
    found: list[dict[str, Any]] = []

    def dfs(node: str, nodes_path: list[str], edges_path: list[dict[str, Any]]) -> None:
        if len(found) >= PATH_LIMIT:
            return
        if len(nodes_path) - 1 >= max_depth:
            return
        for neighbor, edge in adjacency.get(node, []):
            if neighbor in nodes_path:
                # Skip already visited nodes to avoid cycles.
                continue
            new_edge = _edge_repr(edge)
            if neighbor == tgt:
                found.append(
                    {
                        "nodes": nodes_path + [neighbor],
                        "edges": edges_path + [new_edge],
                        "hops": len(nodes_path),
                    }
                )
                if len(found) >= PATH_LIMIT:
                    return
                continue
            dfs(neighbor, nodes_path + [neighbor], edges_path + [new_edge])

    dfs(src, [src], [])
    return found


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_topology(path: Path | str | None = None) -> dict[str, Any]:
    """Load and parse a topology JSON file from disk.

    Args:
        path: Optional path. Defaults to ``topology.json`` next to this file.

    Returns:
        Parsed topology dict (with ``zones``, ``assets``, ``edges`` keys).

    Raises:
        FileNotFoundError: if the file does not exist.
        json.JSONDecodeError: if the file is not valid JSON.
    """
    target = Path(path) if path else DEFAULT_TOPOLOGY_PATH
    if not target.exists():
        raise FileNotFoundError(f"topology file not found: {target}")
    with target.open("r", encoding="utf-8") as f:
        return json.load(f)


def get_topology(topology: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Return the resolved topology dict (default if ``topology`` is None)."""
    return _resolve_topology(topology)


def reload_default_topology() -> dict[str, Any]:
    """Force-reload the default topology from disk and clear adjacency cache."""
    global _default_topology
    _default_topology = load_topology()
    _adjacency_cache.clear()
    return _default_topology


# ---------------------------------------------------------------------------
# Asset lookups
# ---------------------------------------------------------------------------


def find_asset(
    key: str,
    topology: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    """Resolve an asset by ``asset_id`` / ``ip`` / ``name``.

    Returns the matching asset dict, or ``None`` if no asset matches.
    """
    if not key:
        return None
    target = str(key).strip()
    if not target:
        return None
    topo = _resolve_topology(topology)
    for asset in topo.get("assets") or []:
        if (
            asset.get("asset_id") == target
            or asset.get("ip") == target
            or asset.get("name") == target
        ):
            return asset
    return None


def get_neighbors(
    key: str,
    topology: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Return all directly-connected neighbors for the asset identified by ``key``.

    Raises:
        AssetNotFoundError: if ``key`` does not match any asset.
    """
    topo = _resolve_topology(topology)
    asset = find_asset(key, topo)
    if asset is None:
        raise AssetNotFoundError(key)
    aid = asset["asset_id"]
    neighbors: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    asset_index = {a.get("asset_id"): a for a in topo.get("assets") or []}
    for edge in topo.get("edges") or []:
        if edge.get("from") != aid and edge.get("to") != aid:
            continue
        is_outgoing = edge.get("from") == aid
        side = "outgoing" if is_outgoing else "incoming"
        other_id = edge.get("to") if is_outgoing else edge.get("from")
        seen_key = (other_id, edge.get("protocol"), edge.get("port"), side)
        if seen_key in seen:
            continue
        seen.add(seen_key)
        neighbors.append(
            {
                "side": side,
                "edge": _edge_repr(edge),
                "asset": asset_index.get(other_id),
            }
        )
    return {
        "asset_id": aid,
        "name": asset.get("name"),
        "neighbor_count": len(neighbors),
        "neighbors": neighbors,
    }


def get_critical_assets(
    topology: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Return assets whose criticality is ``HIGH`` or ``CRITICAL``."""
    topo = _resolve_topology(topology)
    crits = [
        a
        for a in topo.get("assets") or []
        if str(a.get("criticality", "")).upper() in ("HIGH", "CRITICAL")
    ]
    return {"count": len(crits), "assets": crits}


# ---------------------------------------------------------------------------
# Path & connectivity
# ---------------------------------------------------------------------------


def find_paths(
    source: str,
    target: str,
    max_depth: int = 4,
    topology: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Enumerate allowed paths from ``source`` to ``target``.

    Raises:
        AssetNotFoundError: if either endpoint cannot be resolved.
        ValueError:         if ``max_depth`` is < 1.
    """
    if max_depth < 1:
        raise ValueError("max_depth must be >= 1")
    topo = _resolve_topology(topology)
    src_asset = find_asset(source, topo)
    if src_asset is None:
        raise AssetNotFoundError(source)
    tgt_asset = find_asset(target, topo)
    if tgt_asset is None:
        raise AssetNotFoundError(target)
    paths = _dfs_paths(topo, src_asset["asset_id"], tgt_asset["asset_id"], max_depth)
    return {
        "source": src_asset["asset_id"],
        "target": tgt_asset["asset_id"],
        "max_depth": max_depth,
        "path_count": len(paths),
        "paths": paths,
        "truncated": len(paths) >= PATH_LIMIT,
    }


def check_connectivity(
    source: str,
    target: str,
    topology: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Check whether ``source`` can reach ``target`` within 4 hops.

    Raises:
        AssetNotFoundError: if either endpoint cannot be resolved.
    """
    topo = _resolve_topology(topology)
    src_asset = find_asset(source, topo)
    if src_asset is None:
        raise AssetNotFoundError(source)
    tgt_asset = find_asset(target, topo)
    if tgt_asset is None:
        raise AssetNotFoundError(target)
    paths = _dfs_paths(topo, src_asset["asset_id"], tgt_asset["asset_id"], 4)
    if paths:
        shortest = min(paths, key=lambda p: p["hops"])
        return {
            "connected": True,
            "source": src_asset["asset_id"],
            "target": tgt_asset["asset_id"],
            "shortest_hops": shortest["hops"],
            "shortest_path": shortest["nodes"],
            "alternative_path_count": max(0, len(paths) - 1),
        }
    return {
        "connected": False,
        "source": src_asset["asset_id"],
        "target": tgt_asset["asset_id"],
        "shortest_hops": None,
        "shortest_path": [],
        "alternative_path_count": 0,
    }


# ---------------------------------------------------------------------------
# Strategy impact analysis
# ---------------------------------------------------------------------------

# Severity level ordering used to combine multiple impact signals.
_LEVEL_ORDER: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_LEVEL_REVERSE: list[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# effect x criticality -> impact level lookup table.
_IMPACT_TABLE: dict[str, dict[str, str]] = {
    "disruptive": {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"},
    "partial_disruptive": {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"},
    "network_block": {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"},
    "scope": {"CRITICAL": "MEDIUM", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"},
    # protective / identity / passive / unknown -> no escalation
}

# The cost of breaking a path is determined by the criticality of its
# destination asset. Paths whose destination is below MEDIUM are not flagged.
_TARGET_SEVERITY: dict[str, str] = {
    "CRITICAL": "HIGH",
    "HIGH": "MEDIUM",
    "MEDIUM": "LOW",
    "LOW": "LOW",
}


def _level_max(*levels: str) -> str:
    best = 0
    for lvl in levels:
        best = max(best, _LEVEL_ORDER.get(str(lvl).upper(), 0))
    return _LEVEL_REVERSE[best]


def _action_effect(action_type: str | None) -> str:
    t = (action_type or "").upper()
    if t in DISRUPTIVE_ACTIONS:
        return "disruptive"
    if t in PARTIAL_ACTIONS:
        return "partial_disruptive"
    if t in NETWORK_BLOCK_ACTIONS:
        return "network_block"
    if t in PROTECTIVE_ACTIONS:
        return "protective"
    if t in IDENTITY_ACTIONS:
        return "identity"
    if t in PASSIVE_ACTIONS:
        return "passive"
    return "unknown"


def _detect_affected_paths(
    topology: dict[str, Any],
    disrupted_ids: set[str],
) -> list[dict[str, Any]]:
    """Find cross-zone paths broken by ``disrupted_ids``.

    Only paths whose destination has criticality HIGH or above are returned.
    A representative path (the first found) is reported per (source, target).
    """
    if not disrupted_ids:
        return []
    by_zone: dict[str, list[dict[str, Any]]] = {}
    for asset in topology.get("assets") or []:
        by_zone.setdefault(asset.get("zone", ""), []).append(asset)

    pair_specs: list[tuple[str, str, str]] = [
        ("DMZ", "Database", "DMZ_TO_DATABASE"),
        ("Internal", "Database", "INTERNAL_TO_DATABASE"),
        ("DMZ", "Internal", "DMZ_TO_INTERNAL"),
    ]

    affected_paths: list[dict[str, Any]] = []
    for src_zone, dst_zone, ptype in pair_specs:
        for src_asset in by_zone.get(src_zone, []):
            for dst_asset in by_zone.get(dst_zone, []):
                tgt_crit = str(dst_asset.get("criticality", "LOW")).upper()
                severity = _TARGET_SEVERITY.get(tgt_crit, "LOW")
                if severity == "LOW":
                    continue
                paths = _dfs_paths(
                    topology, src_asset["asset_id"], dst_asset["asset_id"], 5
                )
                for p in paths:
                    nodes = p["nodes"]
                    disrupted = [n for n in nodes if n in disrupted_ids]
                    if disrupted:
                        affected_paths.append(
                            {
                                "path_type": ptype,
                                "severity": severity,
                                "source": src_asset["asset_id"],
                                "target": dst_asset["asset_id"],
                                "target_criticality": tgt_crit,
                                "nodes": nodes,
                                "disrupted_at": disrupted,
                            }
                        )
                        break
    return affected_paths


def _compute_impact_level(
    affected: list[dict[str, Any]],
    affected_paths: list[dict[str, Any]],
) -> str:
    if not affected and not affected_paths:
        return "LOW"
    base = "LOW"
    for entry in affected:
        criticality = str(entry.get("criticality", "LOW")).upper()
        effect = entry.get("effect", "unknown")
        mapping = _IMPACT_TABLE.get(effect)
        if mapping:
            base = _level_max(base, mapping.get(criticality, "LOW"))
    for path in affected_paths:
        base = _level_max(base, str(path.get("severity", "LOW")))
    return base


def _build_recommendation(
    impact_level: str,
    affected: list[dict[str, Any]],
    affected_paths: list[dict[str, Any]],
    unmatched_targets: list[dict[str, Any]],
) -> str:
    parts: list[str] = []
    if impact_level == "CRITICAL":
        parts.append(
            "CRITICAL: strategy will cut off critical assets or core business "
            "paths; require human approval and prepare a full rollback plan."
        )
    elif impact_level == "HIGH":
        parts.append(
            "HIGH: strategy affects high-priority assets or the DMZ->Database "
            "channel; run formal verification, narrow scope and keep TTL <= 1800s."
        )
    elif impact_level == "MEDIUM":
        parts.append(
            "MEDIUM: localized impact; safe to execute but set a TTL-based "
            "auto-rollback and notify the on-call engineer."
        )
    else:
        parts.append("LOW: limited impact; can be executed via the normal flow.")

    if affected_paths:
        types = sorted({p["path_type"] for p in affected_paths})
        parts.append(f"Affected path categories: {', '.join(types)}.")
    if unmatched_targets:
        names = [u["target"] for u in unmatched_targets[:5] if u.get("target")]
        if names:
            parts.append(
                "Targets not found in topology (consider extending the asset "
                f"inventory): {', '.join(names)}."
            )
    return " ".join(parts)


def evaluate_strategy_impact(
    strategy: Any,
    topology: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Evaluate the topology impact of a DefenseStrategy-shaped dict.

    Expected (minimal) input shape::

        {
          "strategyId": "stg-001",
          "actions": [
            {"type": "ISOLATE_POD", "target": "app-payment-01", "parameters": {}}
          ],
          "scope": {"assets": ["app-payment-01"], "namespaces": ["prod"]}
        }

    Returns a dict with ``impact_level``, ``affected_assets``, ``affected_paths``,
    ``unmatched_targets``, ``recommendation`` and a ``summary`` block.

    Raises:
        TypeError: if ``strategy`` is not a dict.
    """
    if not isinstance(strategy, dict):
        raise TypeError("strategy must be a dict")

    topo = _resolve_topology(topology)
    actions = strategy.get("actions") or []
    scope = strategy.get("scope") or {}

    affected: list[dict[str, Any]] = []
    affected_ids: set[str] = set()
    disrupted_ids: set[str] = set()
    unmatched_targets: list[dict[str, Any]] = []

    # 1) Process each action target.
    for action in actions:
        if not isinstance(action, dict):
            continue
        action_type = (action.get("type") or "").upper()
        target = action.get("target") or ""
        effect = _action_effect(action_type)
        asset = find_asset(target, topo)
        if asset is None:
            unmatched_targets.append(
                {
                    "target": target,
                    "action_type": action_type,
                    "effect": effect,
                    "reason": "target not found in topology",
                }
            )
            continue
        aid = asset["asset_id"]
        if effect in DISRUPTING_EFFECTS:
            disrupted_ids.add(aid)
        if aid in affected_ids:
            continue
        affected_ids.add(aid)
        affected.append(
            {
                "asset_id": aid,
                "name": asset.get("name"),
                "ip": asset.get("ip"),
                "zone": asset.get("zone"),
                "criticality": str(asset.get("criticality", "LOW")).upper(),
                "action_type": action_type,
                "effect": effect,
            }
        )

    # 2) Merge scope.assets (effect=scope; not counted as disrupting).
    for s_target in scope.get("assets", []) or []:
        asset = find_asset(s_target, topo)
        if asset is None or asset["asset_id"] in affected_ids:
            continue
        affected_ids.add(asset["asset_id"])
        affected.append(
            {
                "asset_id": asset["asset_id"],
                "name": asset.get("name"),
                "ip": asset.get("ip"),
                "zone": asset.get("zone"),
                "criticality": str(asset.get("criticality", "LOW")).upper(),
                "action_type": "(scope)",
                "effect": "scope",
            }
        )

    # 3) Detect broken cross-zone paths.
    affected_paths = _detect_affected_paths(topo, disrupted_ids)

    # 4) Aggregate impact level + build recommendation text.
    impact_level = _compute_impact_level(affected, affected_paths)
    recommendation = _build_recommendation(
        impact_level, affected, affected_paths, unmatched_targets
    )

    return {
        "strategy_id": strategy.get("strategyId"),
        "impact_level": impact_level,
        "affected_assets": affected,
        "affected_paths": affected_paths,
        "unmatched_targets": unmatched_targets,
        "recommendation": recommendation,
        "summary": {
            "affected_asset_count": len(affected),
            "disrupted_asset_count": len(disrupted_ids),
            "affected_path_count": len(affected_paths),
            "has_critical_asset": any(
                a["criticality"] == "CRITICAL" for a in affected
            ),
            "has_disruptive_action": any(
                a["effect"] in DISRUPTING_EFFECTS for a in affected
            ),
        },
    }
