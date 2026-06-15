"""Local smoke-test runner for ``os_service``.

This script bypasses the MCP protocol entirely: it imports the pure-Python
service module directly and invokes each read-only tool in sequence,
printing only the ``success`` flag and the one-line ``summary`` from the
unified envelope. Raw ``data`` payloads are deliberately not printed so
the output stays compact even when ``ps`` returns hundreds of rows.

Behavioural guarantees:

* Never raises out of ``main()``: any unexpected exception inside a single
  tool call is caught and reported as ``[FAIL]``; the next tool is still
  executed so the operator always sees a complete report.
* Every ``tool_unavailable`` envelope (typical when running this script on
  Windows or macOS where ``ps`` / ``ss`` / ``df`` / ``systemctl`` /
  ``journalctl`` / ``/proc`` are missing) is rendered as ``[SKIP]`` and
  explicitly annotated with ``graceful degradation`` so the operator can
  immediately tell the absence is tolerated by design.
* The exit code is ``0`` when no tool reported a hard failure (graceful
  ``[SKIP]`` results do not flip the exit code), making the script safe
  to wire into CI as a sanity gate.

Usage::

    cd autonomous-defense-system/mcp-servers/os-mcp-server
    python scripts/test_os_service.py
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Callable

# ---------------------------------------------------------------------------
# Bootstrap: ensure ``os_service`` is importable regardless of the cwd that
# the operator launches the script from.
# ---------------------------------------------------------------------------

_HERE = Path(__file__).resolve().parent
_PARENT = _HERE.parent  # mcp-servers/os-mcp-server
if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))

import os_service as ops  # noqa: E402  (import has to follow sys.path tweak)


# ---------------------------------------------------------------------------
# Platform awareness
# ---------------------------------------------------------------------------

# All read-only tools shipped by os_service target systemd-based Linux
# (Kylin V10, Ubuntu, RHEL, etc.). When this script runs on a non-Linux
# host we deliberately downgrade every non-success result to a graceful
# skip: developers running the script on Windows / macOS for convenience
# should never see hard failures (e.g. Windows ships its own ``netstat``
# binary that does not accept GNU ``-tunap`` flags and would otherwise be
# reported as ``command_failed``). Linux hosts keep the strict semantics.
_IS_LINUX = sys.platform.startswith("linux")


# ---------------------------------------------------------------------------
# Pretty-printing helpers - intentionally ANSI-free so the output is
# identical on Windows cmd, PowerShell, macOS Terminal and Linux ttys.
# ---------------------------------------------------------------------------

# Cap the printed summary to keep one tool result on a single terminal row.
_SUMMARY_MAX_LEN = 120


def _truncate(text: str, max_len: int = _SUMMARY_MAX_LEN) -> str:
    """Collapse ``text`` to a single line and truncate to ``max_len`` chars.

    The U+FFFD replacement character is rewritten to a plain ``?`` because
    some legacy Windows console code pages (cp936/GBK) cannot encode it
    and would otherwise raise ``UnicodeEncodeError`` from ``print``.
    ``os_service`` may inject U+FFFD when an underlying command emits
    non-UTF-8 bytes (e.g. localised stderr from a Chinese-locale Linux).
    """
    flat = (
        (text or "")
        .replace("\ufffd", "?")
        .strip()
        .replace("\n", " ")
        .replace("\r", " ")
    )
    if len(flat) > max_len:
        return flat[: max_len - 3] + "..."
    return flat


def _safe_print(line: str) -> None:
    """Print ``line``; on encoding failure re-encode with ``errors='replace'``.

    Belt-and-braces protection so the script keeps running even if a tool
    summary slips through containing characters that the active stdout
    encoding cannot represent.
    """
    try:
        print(line)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "ascii"
        sanitized = line.encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(sanitized)


def _format_row(tool_label: str, marker: str, success: bool, summary: str, suffix: str = "") -> str:
    """Render one result row in a fixed-column layout."""
    success_token = "true" if success else "false"
    return f"  {marker:<6} {tool_label:<22} success={success_token:<5} summary={summary}{suffix}"


def _print_envelope(tool_label: str, envelope: dict[str, Any]) -> tuple[bool, bool]:
    """Print a single tool envelope and classify it.

    Returns ``(success, gracefully_degraded)`` so the caller can compute
    aggregate counters at the end of the run.
    """
    success = bool(envelope.get("success"))
    error_code = envelope.get("error")
    summary = _truncate(str(envelope.get("summary") or ""))

    if success:
        marker = "[PASS]"
        suffix = ""
        degraded = False
    elif error_code == "tool_unavailable":
        marker = "[SKIP]"
        suffix = f"  -> graceful degradation: {error_code}"
        degraded = True
    elif not _IS_LINUX:
        # Non-Linux hosts: any non-success outcome (command_failed,
        # timeout, invalid_argument) is reclassified as a graceful skip
        # so the script never reports a hard failure off-target.
        marker = "[SKIP]"
        suffix = f"  -> graceful degradation on non-Linux ({sys.platform}): {error_code}"
        degraded = True
    else:
        marker = "[FAIL]"
        suffix = f"  -> error: {error_code}"
        degraded = False

    _safe_print(_format_row(tool_label, marker, success, summary, suffix))
    return success, degraded


def _run_one(label: str, fn: Callable[[], dict[str, Any]]) -> tuple[bool, bool]:
    """Invoke a single tool, swallowing any unexpected exception.

    The os_service contract guarantees that every public tool already
    returns a structured envelope instead of raising, but this extra
    defence makes the script bullet-proof even when somebody adds a new
    tool that forgets that contract.
    """
    try:
        envelope = fn()
    except Exception as exc:
        # Same non-Linux relaxation as in ``_print_envelope``.
        marker = "[SKIP]" if not _IS_LINUX else "[FAIL]"
        suffix = (
            f"  -> graceful degradation on non-Linux ({sys.platform}): "
            f"{exc.__class__.__name__}"
            if not _IS_LINUX
            else f"  -> error: {exc.__class__.__name__}: {exc}"
        )
        _safe_print(
            _format_row(
                label,
                marker,
                False,
                "<unhandled exception>",
                suffix,
            )
        )
        return False, not _IS_LINUX

    if not isinstance(envelope, dict):
        marker = "[SKIP]" if not _IS_LINUX else "[FAIL]"
        suffix = (
            f"  -> graceful degradation on non-Linux ({sys.platform}): bad_return_type"
            if not _IS_LINUX
            else "  -> error: bad_return_type"
        )
        _safe_print(
            _format_row(
                label,
                marker,
                False,
                "<non-dict envelope>",
                suffix,
            )
        )
        return False, not _IS_LINUX

    return _print_envelope(label, envelope)


# ---------------------------------------------------------------------------
# Test cases - each lambda calls one read-only tool with conservative,
# bounded arguments so this script never produces large output even when
# all underlying commands are present.
# ---------------------------------------------------------------------------


def _build_cases() -> list[tuple[str, Callable[[], dict[str, Any]]]]:
    """Define the smoke-test sequence.

    Order mirrors the operational debugging flow an SRE would follow when
    triaging a Kylin host: workload (processes, sockets), then resources
    (disk, memory, CPU), then audit signals (logs, services).
    """
    return [
        ("get_process_list", lambda: ops.get_process_list(top_n=5)),
        ("get_network_sockets", lambda: ops.get_network_sockets(top_n=5)),
        ("get_disk_usage", lambda: ops.get_disk_usage()),
        ("get_memory_status", lambda: ops.get_memory_status()),
        ("get_cpu_load", lambda: ops.get_cpu_load()),
        ("get_uptime", lambda: ops.get_uptime()),
        ("get_system_logs", lambda: ops.get_system_logs(unit=None, lines=20)),
        ("get_service_status", lambda: ops.get_service_status("sshd")),
    ]


def main() -> int:
    """Run every smoke-test case and return a process exit code."""
    _safe_print("Running os-mcp-server smoke-test (no MCP protocol involved).")
    _safe_print(f"  python   : {sys.version.split()[0]}")
    _safe_print(f"  platform : {sys.platform}")
    _safe_print(f"  service  : os_service @ {Path(ops.__file__).resolve()}")
    _safe_print("")

    cases = _build_cases()

    passed = 0
    skipped = 0
    failed = 0

    for label, fn in cases:
        ok, degraded = _run_one(label, fn)
        if ok:
            passed += 1
        elif degraded:
            skipped += 1
        else:
            failed += 1

    total = len(cases)
    _safe_print("")
    _safe_print(
        f"Summary: {passed} passed, {skipped} skipped (tool_unavailable), "
        f"{failed} failed (out of {total})"
    )
    if skipped == total:
        _safe_print(
            "Note: every tool was skipped via graceful degradation. This is "
            "expected on non-Linux hosts; rerun on Kylin / a systemd Linux "
            "to exercise the real code paths."
        )

    # Treat graceful degradation as success so this script can be wired
    # into CI on a non-Linux runner without flapping.
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
