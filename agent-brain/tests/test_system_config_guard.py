"""Unit tests for ``agent_brain.safety.system_config_guard``."""
from __future__ import annotations

import unittest

from agent_brain.safety.system_config_guard import (
    DECISION_ALLOW,
    DECISION_BLOCK,
    evaluate,
)

_HIGH_OR_CRITICAL = {"HIGH", "CRITICAL"}


class SystemConfigGuardBlockTests(unittest.TestCase):
    """Every entry in this matrix must trigger a BLOCK envelope."""

    def assert_blocks(self, command: str, *, expected_paths: list[str] | None = None) -> None:
        envelope = evaluate(candidate_commands=[command])
        self.assertEqual(envelope.decision, DECISION_BLOCK, msg=command)
        self.assertIn(envelope.riskLevel, _HIGH_OR_CRITICAL, msg=command)
        if expected_paths:
            labels = {m.label for m in envelope.matchedPaths}
            for p in expected_paths:
                self.assertIn(p, labels, msg=command)
        # Chinese reason must always be present for the UI.
        self.assertTrue(envelope.reasonZh)

    def test_tee_passwd_blocked(self) -> None:
        self.assert_blocks(
            "echo 'hacker:x:0:0::/:/bin/sh' | sudo tee -a /etc/passwd",
            expected_paths=["/etc/passwd"],
        )

    def test_sed_inplace_sudoers_blocked(self) -> None:
        self.assert_blocks("sed -i 's/foo/bar/' /etc/sudoers", expected_paths=["/etc/sudoers*"])

    def test_redirect_to_shadow_blocked(self) -> None:
        self.assert_blocks("echo x > /etc/shadow", expected_paths=["/etc/shadow"])

    def test_cp_grub_blocked(self) -> None:
        envelope = evaluate(candidate_commands=["cp evil /boot/grub/grub.cfg"])
        self.assertEqual(envelope.decision, DECISION_BLOCK)
        self.assertIn("/boot/*", {m.label for m in envelope.matchedPaths})

    def test_chmod_systemd_unit_blocked(self) -> None:
        envelope = evaluate(
            candidate_commands=["chmod 777 /etc/systemd/system/sshd.service"]
        )
        self.assertEqual(envelope.decision, DECISION_BLOCK)
        self.assertEqual(envelope.matchedVerb, "chmod")

    def test_chown_sshd_config_blocked(self) -> None:
        envelope = evaluate(
            candidate_commands=["chown -R root:root /etc/ssh/sshd_config"]
        )
        self.assertEqual(envelope.decision, DECISION_BLOCK)
        self.assertIn("/etc/ssh/sshd_config*", {m.label for m in envelope.matchedPaths})

    def test_natural_language_overwrite_passwd_blocked(self) -> None:
        # No candidate commands, but the instruction expresses both a
        # write intent (覆盖) and a protected path.
        envelope = evaluate(instruction="请覆盖 /etc/passwd 文件")
        self.assertEqual(envelope.decision, DECISION_BLOCK)
        self.assertEqual(envelope.matchedPaths[0].matchedIn, "instruction")


class SystemConfigGuardAllowTests(unittest.TestCase):
    """Read-only / unrelated requests must be ALLOW."""

    def test_cat_hostname_allowed(self) -> None:
        envelope = evaluate(candidate_commands=["cat /etc/hostname"])
        self.assertEqual(envelope.decision, DECISION_ALLOW)
        self.assertEqual(envelope.matchedPaths, [])

    def test_nl_question_about_passwd_allowed(self) -> None:
        # Asking about /etc/passwd without a write verb must NOT block.
        envelope = evaluate(instruction="什么是 /etc/passwd 文件？")
        self.assertEqual(envelope.decision, DECISION_ALLOW)

    def test_empty_inputs_allowed(self) -> None:
        envelope = evaluate(candidate_commands=[], instruction="")
        self.assertEqual(envelope.decision, DECISION_ALLOW)
        self.assertEqual(envelope.matchedVerb, None)

    def test_unrelated_disk_command_allowed(self) -> None:
        envelope = evaluate(candidate_commands=["df -h"])
        self.assertEqual(envelope.decision, DECISION_ALLOW)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
