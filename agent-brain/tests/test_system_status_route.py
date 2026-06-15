"""End-to-end tests for ``GET /system/status``."""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from agent_brain.main import app


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


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
