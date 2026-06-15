"""End-to-end tests for ``GET /audit/{request_id}``.

The route serves a single audit-<requestId>.json file from the
:class:`AuditLogger` directory and must reject any path-traversal
attempts before touching the filesystem.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from agent_brain.audit.audit_logger import AuditLogger
from agent_brain.main import app, get_audit_logger


class AuditDownloadRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.logger = AuditLogger(directory=self.dir, enabled=True)
        app.dependency_overrides[get_audit_logger] = lambda: self.logger
        self.client = TestClient(app)

    def tearDown(self) -> None:
        app.dependency_overrides.pop(get_audit_logger, None)
        self._tmp.cleanup()

    def _write(self, request_id: str, payload: dict) -> Path:
        target = self.dir / f"audit-{request_id}.json"
        target.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return target

    def test_existing_id_returns_200_and_json_body(self) -> None:
        self._write("ops-abc123", {"requestId": "ops-abc123", "ok": True})
        resp = self.client.get("/audit/ops-abc123")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertIn("application/json", resp.headers["content-type"].lower())
        body = resp.json()
        self.assertEqual(body["requestId"], "ops-abc123")
        self.assertTrue(body["ok"])

    def test_missing_id_returns_404(self) -> None:
        resp = self.client.get("/audit/ops-nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_path_traversal_attempt_rejected(self) -> None:
        # FastAPI may normalise some traversal forms at the routing layer
        # (returning 404 instead of 400). Either response is acceptable
        # as long as we never serve a file outside the audit directory.
        for evil in ("../etc/passwd", "..%2Fetc%2Fpasswd", "ops/../../../etc"):
            resp = self.client.get(f"/audit/{evil}")
            self.assertIn(
                resp.status_code, (400, 404), msg=f"{evil} -> {resp.status_code}"
            )

    def test_invalid_characters_rejected(self) -> None:
        for evil in ("ops with spaces", "ops$$$", "ops;rm", "ops%00"):
            resp = self.client.get(f"/audit/{evil}")
            self.assertIn(resp.status_code, (400, 404))

    def test_request_id_at_max_length_accepted(self) -> None:
        rid = "a" * 80
        self._write(rid, {"requestId": rid})
        resp = self.client.get(f"/audit/{rid}")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
