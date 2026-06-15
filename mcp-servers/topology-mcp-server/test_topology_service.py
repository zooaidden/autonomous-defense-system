"""Unit tests for ``topology_service``.

Run from this directory:

    python -m unittest test_topology_service.py    # built-in runner
    python test_topology_service.py                 # equivalent
    pytest -q                                       # pytest also works

These tests do not import the MCP server and do not require the ``mcp``
package to be installed. They cover:

    * find_asset (existing by id/ip/name; missing/empty key -> None)
    * get_neighbors (DMZ api gateway and unknown asset)
    * get_critical_assets (HIGH and CRITICAL only)
    * find_paths (DMZ -> Database, missing endpoints, invalid depth)
    * check_connectivity (DMZ web -> DB primary, blocked direct edge,
      reverse direction)
    * evaluate_strategy_impact (block on critical, isolate critical,
      isolate low-value, block external IP, protective WAF rule, type guard)
    * Custom (mini) topology to confirm the topology argument is honored.
"""
from __future__ import annotations

import unittest

import topology_service as ts
from topology_service import AssetNotFoundError


# ---------------------------------------------------------------------------
# Asset lookup
# ---------------------------------------------------------------------------


class FindAssetTests(unittest.TestCase):
    """Cover existing/missing/empty inputs to ``find_asset``."""

    def test_find_existing_asset_by_id(self) -> None:
        asset = ts.find_asset("app-payment-01")
        self.assertIsNotNone(asset)
        assert asset is not None  # for type narrowing
        self.assertEqual(asset["asset_id"], "app-payment-01")
        self.assertEqual(asset["zone"], "Internal")
        self.assertEqual(asset["criticality"], "CRITICAL")

    def test_find_existing_asset_by_ip(self) -> None:
        asset = ts.find_asset("10.30.1.10")
        self.assertIsNotNone(asset)
        assert asset is not None
        self.assertEqual(asset["asset_id"], "db-primary-01")

    def test_find_existing_asset_by_name(self) -> None:
        asset = ts.find_asset("kafka-broker")
        self.assertIsNotNone(asset)
        assert asset is not None
        self.assertEqual(asset["asset_id"], "svc-broker-01")

    def test_find_missing_asset_returns_none(self) -> None:
        self.assertIsNone(ts.find_asset("nonexistent-asset"))
        self.assertIsNone(ts.find_asset("203.0.113.10"))

    def test_find_empty_or_whitespace_returns_none(self) -> None:
        self.assertIsNone(ts.find_asset(""))
        self.assertIsNone(ts.find_asset("   "))


# ---------------------------------------------------------------------------
# Neighbors
# ---------------------------------------------------------------------------


class GetNeighborsTests(unittest.TestCase):
    def test_neighbors_of_dmz_api(self) -> None:
        result = ts.get_neighbors("dmz-api-01")
        self.assertEqual(result["asset_id"], "dmz-api-01")
        self.assertEqual(result["name"], "api-gateway")
        self.assertGreaterEqual(result["neighbor_count"], 4)

        # api-gateway should fan out to payment / auth / order services.
        outgoing_ids = {
            n["edge"]["to"] for n in result["neighbors"] if n["side"] == "outgoing"
        }
        self.assertIn("app-payment-01", outgoing_ids)
        self.assertIn("app-auth-01", outgoing_ids)
        self.assertIn("app-order-01", outgoing_ids)

        # And receive from the web gateway (incoming).
        incoming_ids = {
            n["edge"]["from"] for n in result["neighbors"] if n["side"] == "incoming"
        }
        self.assertIn("dmz-web-01", incoming_ids)

    def test_neighbors_of_missing_asset_raises(self) -> None:
        with self.assertRaises(AssetNotFoundError) as cm:
            ts.get_neighbors("does-not-exist")
        self.assertEqual(cm.exception.key, "does-not-exist")


# ---------------------------------------------------------------------------
# Critical assets
# ---------------------------------------------------------------------------


class GetCriticalAssetsTests(unittest.TestCase):
    def test_only_high_or_critical_returned(self) -> None:
        result = ts.get_critical_assets()
        self.assertGreater(result["count"], 0)
        for asset in result["assets"]:
            self.assertIn(asset["criticality"].upper(), {"HIGH", "CRITICAL"})

    def test_known_critical_assets_listed(self) -> None:
        ids = {a["asset_id"] for a in ts.get_critical_assets()["assets"]}
        self.assertIn("app-payment-01", ids)  # CRITICAL
        self.assertIn("app-auth-01", ids)     # CRITICAL
        self.assertIn("db-primary-01", ids)   # CRITICAL
        self.assertIn("dmz-api-01", ids)      # HIGH

    def test_low_or_medium_assets_excluded(self) -> None:
        ids = {a["asset_id"] for a in ts.get_critical_assets()["assets"]}
        self.assertNotIn("app-inventory-01", ids)  # MEDIUM
        self.assertNotIn("db-analytics-01", ids)   # MEDIUM
        self.assertNotIn("mgmt-ci-01", ids)        # MEDIUM


# ---------------------------------------------------------------------------
# Path enumeration
# ---------------------------------------------------------------------------


class FindPathsTests(unittest.TestCase):
    def test_dmz_api_to_db_primary_paths(self) -> None:
        result = ts.find_paths("dmz-api-01", "db-primary-01", max_depth=4)
        self.assertGreater(result["path_count"], 0)
        self.assertEqual(result["source"], "dmz-api-01")
        self.assertEqual(result["target"], "db-primary-01")

        for path in result["paths"]:
            self.assertEqual(path["nodes"][0], "dmz-api-01")
            self.assertEqual(path["nodes"][-1], "db-primary-01")
            self.assertLessEqual(path["hops"], 4)
            # Each path must have hops == len(edges).
            self.assertEqual(path["hops"], len(path["edges"]))

        # At least one path should run through the payment service.
        node_lists = [p["nodes"] for p in result["paths"]]
        self.assertTrue(
            any("app-payment-01" in nodes for nodes in node_lists),
            f"expected one path through payment-service; got {node_lists}",
        )

    def test_blocked_direct_edge_excluded_from_paths(self) -> None:
        # Edge dmz-web-01 -> db-primary-01 has allowed=false in topology.json.
        # No path should consist of that single hop.
        result = ts.find_paths("dmz-web-01", "db-primary-01", max_depth=1)
        self.assertEqual(result["path_count"], 0)

    def test_missing_source_raises(self) -> None:
        with self.assertRaises(AssetNotFoundError):
            ts.find_paths("ghost-asset", "db-primary-01")

    def test_missing_target_raises(self) -> None:
        with self.assertRaises(AssetNotFoundError):
            ts.find_paths("dmz-api-01", "ghost-asset")

    def test_invalid_max_depth_raises(self) -> None:
        with self.assertRaises(ValueError):
            ts.find_paths("dmz-api-01", "db-primary-01", max_depth=0)


# ---------------------------------------------------------------------------
# Connectivity
# ---------------------------------------------------------------------------


class CheckConnectivityTests(unittest.TestCase):
    def test_dmz_web_reaches_db_primary(self) -> None:
        result = ts.check_connectivity("dmz-web-01", "db-primary-01")
        self.assertTrue(result["connected"])
        self.assertEqual(result["shortest_path"][0], "dmz-web-01")
        self.assertEqual(result["shortest_path"][-1], "db-primary-01")
        self.assertIsInstance(result["shortest_hops"], int)
        # The blocked direct edge must not be used; shortest path > 1 hop.
        self.assertGreater(result["shortest_hops"], 1)

    def test_database_cannot_initiate_back_to_dmz(self) -> None:
        # All edges in the mock topology are outbound, so the database
        # cannot initiate a connection back to the DMZ.
        result = ts.check_connectivity("db-primary-01", "dmz-web-01")
        self.assertFalse(result["connected"])
        self.assertIsNone(result["shortest_hops"])
        self.assertEqual(result["shortest_path"], [])

    def test_missing_endpoint_raises(self) -> None:
        with self.assertRaises(AssetNotFoundError):
            ts.check_connectivity("dmz-web-01", "ghost-asset")


# ---------------------------------------------------------------------------
# Strategy impact
# ---------------------------------------------------------------------------


class EvaluateStrategyImpactTests(unittest.TestCase):
    def test_block_critical_asset_marks_high_impact(self) -> None:
        # BLOCK_IP on a CRITICAL asset's IP is expected to be HIGH.
        result = ts.evaluate_strategy_impact(
            {
                "strategyId": "stg-block-critical",
                "actions": [{"type": "BLOCK_IP", "target": "10.30.1.10"}],
            }
        )
        self.assertEqual(result["impact_level"], "HIGH")
        self.assertEqual(len(result["affected_assets"]), 1)
        affected = result["affected_assets"][0]
        self.assertEqual(affected["asset_id"], "db-primary-01")
        self.assertEqual(affected["effect"], "network_block")
        self.assertEqual(affected["criticality"], "CRITICAL")
        self.assertEqual(result["unmatched_targets"], [])
        self.assertTrue(result["summary"]["has_critical_asset"])
        self.assertTrue(result["summary"]["has_disruptive_action"])

    def test_isolate_critical_asset_marks_critical_and_breaks_dmz_to_db(self) -> None:
        result = ts.evaluate_strategy_impact(
            {
                "strategyId": "stg-isolate-payment",
                "actions": [{"type": "ISOLATE_POD", "target": "app-payment-01"}],
            }
        )
        self.assertEqual(result["impact_level"], "CRITICAL")
        self.assertGreater(result["summary"]["affected_path_count"], 0)
        path_types = {p["path_type"] for p in result["affected_paths"]}
        self.assertIn("DMZ_TO_DATABASE", path_types)

    def test_isolate_low_value_endpoint_marks_medium(self) -> None:
        # Inventory is MEDIUM and only on the path to db-replica (HIGH).
        result = ts.evaluate_strategy_impact(
            {
                "strategyId": "stg-isolate-inventory",
                "actions": [{"type": "ISOLATE_POD", "target": "app-inventory-01"}],
            }
        )
        self.assertEqual(result["impact_level"], "MEDIUM")

    def test_block_external_ip_marks_low_with_unmatched_target(self) -> None:
        result = ts.evaluate_strategy_impact(
            {
                "strategyId": "stg-block-external",
                "actions": [{"type": "BLOCK_IP", "target": "203.0.113.10"}],
            }
        )
        self.assertEqual(result["impact_level"], "LOW")
        self.assertEqual(result["affected_assets"], [])
        self.assertEqual(len(result["unmatched_targets"]), 1)
        self.assertEqual(result["unmatched_targets"][0]["target"], "203.0.113.10")

    def test_protective_action_does_not_escalate(self) -> None:
        result = ts.evaluate_strategy_impact(
            {
                "strategyId": "stg-waf",
                "actions": [{"type": "APPLY_WAF_RULE", "target": "dmz-api-01"}],
            }
        )
        self.assertEqual(result["impact_level"], "LOW")
        self.assertEqual(result["affected_paths"], [])
        self.assertFalse(result["summary"]["has_disruptive_action"])

    def test_recommendation_text_matches_level(self) -> None:
        result = ts.evaluate_strategy_impact(
            {
                "strategyId": "stg-1",
                "actions": [{"type": "ISOLATE_POD", "target": "app-payment-01"}],
            }
        )
        self.assertIn("CRITICAL", result["recommendation"])

    def test_strategy_must_be_dict(self) -> None:
        with self.assertRaises(TypeError):
            ts.evaluate_strategy_impact("not-a-dict")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Custom (mini) topology
# ---------------------------------------------------------------------------


TINY_TOPOLOGY: dict = {
    "zones": [{"id": "DMZ"}, {"id": "Database"}],
    "assets": [
        {
            "asset_id": "edge-1",
            "name": "edge",
            "ip": "1.1.1.1",
            "zone": "DMZ",
            "role": "edge",
            "criticality": "HIGH",
            "services": [],
            "tags": [],
        },
        {
            "asset_id": "db-1",
            "name": "db",
            "ip": "2.2.2.2",
            "zone": "Database",
            "role": "rdbms",
            "criticality": "CRITICAL",
            "services": [],
            "tags": [],
        },
    ],
    "edges": [
        {
            "from": "edge-1",
            "to": "db-1",
            "protocol": "TCP",
            "port": 5432,
            "direction": "outbound",
            "allowed": True,
        }
    ],
}


class CustomTopologyTests(unittest.TestCase):
    """Confirm that the optional ``topology`` argument is honored end-to-end."""

    def test_find_asset_with_custom_topology(self) -> None:
        asset = ts.find_asset("db-1", topology=TINY_TOPOLOGY)
        self.assertIsNotNone(asset)
        assert asset is not None
        self.assertEqual(asset["zone"], "Database")
        # Default topology should not contain this asset id.
        self.assertIsNone(ts.find_asset("db-1"))

    def test_find_paths_with_custom_topology(self) -> None:
        result = ts.find_paths(
            "edge-1", "db-1", max_depth=2, topology=TINY_TOPOLOGY
        )
        self.assertEqual(result["path_count"], 1)
        self.assertEqual(result["paths"][0]["nodes"], ["edge-1", "db-1"])

    def test_evaluate_strategy_impact_with_custom_topology(self) -> None:
        # Isolating edge-1 (HIGH) is itself HIGH, and it cuts the only
        # DMZ -> Database path whose destination db-1 is CRITICAL,
        # contributing severity HIGH. Final level = HIGH.
        result = ts.evaluate_strategy_impact(
            {
                "strategyId": "stg-tiny",
                "actions": [{"type": "ISOLATE_HOST", "target": "edge-1"}],
            },
            topology=TINY_TOPOLOGY,
        )
        self.assertEqual(result["impact_level"], "HIGH")
        self.assertEqual(len(result["affected_assets"]), 1)
        self.assertEqual(result["affected_assets"][0]["asset_id"], "edge-1")
        self.assertGreater(len(result["affected_paths"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
