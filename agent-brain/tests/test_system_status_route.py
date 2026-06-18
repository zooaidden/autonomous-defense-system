"""End-to-end tests for ``GET /system/status``."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from agent_brain.main import _probe_service_status, app


class SystemStatusRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_returns_200_with_expected_top_level_keys(self) -> None:
        resp = self.client.get("/system/status")
        self.assertEqual(resp.status_code, 200, resp.text)
        body = resp.json()
        for key in ("platform", "services", "mcpClients", "executor", "guards", "auditFile"):
            self.assertIn(key, body, msg=key)

    def test_platform_block_shape(self) -> None:
        body = self.client.get("/system/status").json()
        platform = body["platform"]
        for key in (
            "system",
            "release",
            "machine",
            "hostname",
            "python",
            "isLoongArch",
        ):
            self.assertIn(key, platform, msg=key)
        self.assertIsInstance(platform["isLoongArch"], bool)

    def test_executor_whitelist_is_non_empty_and_sorted(self) -> None:
        body = self.client.get("/system/status").json()
        whitelist = body["executor"]["whitelist"]
        self.assertIsInstance(whitelist, list)
        self.assertGreater(len(whitelist), 0)
        self.assertEqual(whitelist, sorted(whitelist))
        # Sanity: a few well-known read-only tools must be present.
        for required in ("df", "free", "ps", "ss"):
            self.assertIn(required, whitelist)

    def test_mcp_clients_block_has_os_entry(self) -> None:
        body = self.client.get("/system/status").json()
        os_client = body["mcpClients"]["os"]
        self.assertIn("enabled", os_client)
        self.assertIn("mode", os_client)
        self.assertIn("tools", os_client)
        self.assertIn("get_uptime", os_client["tools"])

    def test_services_list_includes_agent_brain(self) -> None:
        body = self.client.get("/system/status").json()
        names = [s["name"] for s in body["services"]]
        self.assertIn("agent-brain", names)

    def test_services_include_probe_statuses(self) -> None:
        with patch("agent_brain.main._probe_service_status", return_value="up"):
            body = self.client.get("/system/status").json()
        by_name = {s["name"]: s for s in body["services"]}
        for name in (
            "defense-gateway",
            "actuator-service",
            "formal-verifier",
            "dashboard-ui",
        ):
            self.assertEqual(by_name[name]["status"], "up")
            self.assertIn("url", by_name[name])

    def test_actuator_mcp_reflects_in_process_guard(self) -> None:
        body = self.client.get("/system/status").json()
        actuator = body["mcpClients"]["actuator"]
        self.assertTrue(actuator["enabled"])
        self.assertEqual(actuator["mode"], "in-process")
        self.assertIn("actuator-mcp-server", actuator["serverPath"])
        self.assertIn("execute_strategy", actuator["tools"])

    def test_probe_service_status_maps_http_outcomes(self) -> None:
        class Response:
            def __init__(self, status_code: int) -> None:
                self.status_code = status_code

        with patch("agent_brain.main.httpx.get", return_value=Response(200)):
            self.assertEqual(_probe_service_status("http://svc", "/health"), "up")
        with patch("agent_brain.main.httpx.get", return_value=Response(404)):
            self.assertEqual(_probe_service_status("http://svc", "/health"), "down")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
