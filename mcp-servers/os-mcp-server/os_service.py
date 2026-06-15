from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform detection (consumed by agent-brain dashboard & start scripts)
# ---------------------------------------------------------------------------
import platform as _platform

_LOONGARCH = _platform.machine().lower() in {"loongarch64", "loong64"}
_KYLIN = Path("/etc/kylin-release").exists()


# ---------------------------------------------------------------------------
# Public constants - timeouts and output caps
# ---------------------------------------------------------------------------

# Default per-command timeout in seconds. Most local enumerations finish in
# well under a second; the longer ``LOG_TIMEOUT_SECONDS`` is used for
# journalctl which may need to scan a large journal.
DEFAULT_TIMEOUT_SECONDS: float = 5.0
SERVICE_TIMEOUT_SECONDS: float = 8.0
LOG_TIMEOUT_SECONDS: float = 10.0

# Hard cap on how many raw bytes we keep from a single command. Anything
# beyond this is silently dropped before parsing to protect the caller.
MAX_STDOUT_BYTES: int = 256 * 1024
MAX_STDERR_BYTES: int = 16 * 1024

# Defaults / clamps for list-shaped tools. These keep responses bounded so
# upstream LLMs and dashboards never have to deal with thousands of rows.
DEFAULT_PROCESS_LIMIT: int = 50
MAX_PROCESS_LIMIT: int = 500
DEFAULT_SOCKET_LIMIT: int = 500
MAX_SOCKET_LIMIT: int = 2000
DEFAULT_OPEN_FILES_LIMIT: int = 200
MAX_OPEN_FILES_LIMIT: int = 2000
DEFAULT_LOG_LINES: int = 200
MAX_LOG_LINES: int = 2000
DEFAULT_STATUS_TAIL_LINES: int = 20

# Name validation: service / unit names accepted by systemd are alphanum
# plus ``. _ - @``. Reject anything starting with ``-`` so it can never be
# parsed as a CLI flag by an underlying binary.
_SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9_@.\-]{1,128}$")

# Path validation for lsof: absolute path, no shell metacharacters, no NUL.
_PATH_FORBIDDEN_CHARS = set(" \t\n\r\x00`$\\\"'<>|&;*?()[]{}!~")

# Allowed ``--since`` shorthand for journalctl: limited charset and length.
_JOURNAL_SINCE_RE = re.compile(r"^[A-Za-z0-9 :,.\-]{1,64}$")


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------


def _envelope(
    *,
    success: bool,
    tool: str,
    data: Any,
    summary: str,
    error: str | None,
) -> dict[str, Any]:
    """Build the canonical response envelope used by every tool.

    Keeping this in one place guarantees the keys, key order and types
    stay identical across tools so callers can rely on a stable shape.
    """
    return {
        "success": bool(success),
        "tool": tool,
        "data": data,
        "summary": summary,
        "error": error,
    }


def _ok(tool: str, data: Any, summary: str) -> dict[str, Any]:
    """Convenience wrapper for a successful response."""
    return _envelope(success=True, tool=tool, data=data, summary=summary, error=None)


def _err(tool: str, summary: str, error: str, *, data: Any = None) -> dict[str, Any]:
    """Convenience wrapper for a failure response."""
    return _envelope(success=False, tool=tool, data=data, summary=summary, error=error)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def _which(command: str) -> str | None:
    """Resolve ``command`` to an absolute path via ``$PATH`` or return None."""
    return shutil.which(command)


def _decode_truncate(blob: bytes | None, cap: int) -> str:
    """Decode bytes as UTF-8 with replacement and truncate to ``cap`` bytes.

    Truncation is performed on the byte stream before decoding so a long
    output cannot blow up downstream JSON serialization. A trailing marker
    is appended when the stream was actually truncated so callers can tell.
    """
    if not blob:
        return ""
    truncated = False
    if len(blob) > cap:
        blob = blob[:cap]
        truncated = True
    text = blob.decode("utf-8", errors="replace")
    if truncated:
        text += "\n... [truncated]"
    return text


def _run_command(
    argv: list[str],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[int, str, str, str | None]:
    """Run ``argv`` via :func:`subprocess.run` (argv form, never shell).

    Returns ``(returncode, stdout, stderr, error_code)``. ``error_code`` is
    ``None`` on a clean run, otherwise one of the stable codes documented
    on the module docstring (``timeout``, ``command_not_found``,
    ``command_failed``). The caller is responsible for inspecting the
    return code for the non-zero case.
    """
    if not argv:
        return -1, "", "", "command_failed"

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        # Binary missing entirely - report as tool_unavailable upstream.
        logger.debug("command not found: %s", argv[0])
        return -1, "", "", "command_not_found"
    except PermissionError as exc:
        logger.warning("permission denied running %s: %s", argv[0], exc)
        return -1, "", "", "command_failed"
    except subprocess.TimeoutExpired as exc:
        logger.warning(
            "command timed out after %.1fs: %s", timeout, " ".join(argv)
        )
        # ``exc`` carries any partial output captured before the kill.
        stdout = _decode_truncate(exc.stdout if isinstance(exc.stdout, (bytes, bytearray)) else None, MAX_STDOUT_BYTES)
        stderr = _decode_truncate(exc.stderr if isinstance(exc.stderr, (bytes, bytearray)) else None, MAX_STDERR_BYTES)
        return -1, stdout, stderr, "timeout"
    except OSError as exc:
        logger.warning("OS error running %s: %s", argv[0], exc)
        return -1, "", "", "command_failed"

    stdout = _decode_truncate(proc.stdout, MAX_STDOUT_BYTES)
    stderr = _decode_truncate(proc.stderr, MAX_STDERR_BYTES)
    return proc.returncode, stdout, stderr, None


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------


def _clamp(value: int | None, *, default: int, min_value: int, max_value: int) -> int:
    """Clamp ``value`` into ``[min_value, max_value]`` with a fallback default.

    Non-int / non-positive inputs fall back to ``default`` so tool authors
    do not need to repeat the same defensive checks in every function body.
    """
    if value is None:
        return default
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return default
    if ivalue < min_value:
        return min_value
    if ivalue > max_value:
        return max_value
    return ivalue


def _validate_service_name(name: str) -> str | None:
    """Return ``name`` if it is a syntactically safe systemd unit name.

    Returns ``None`` when the input is missing or unsafe so callers can
    short-circuit with an ``invalid_argument`` envelope.
    """
    if not isinstance(name, str):
        return None
    candidate = name.strip()
    if not candidate or candidate.startswith("-"):
        return None
    if not _SERVICE_NAME_RE.match(candidate):
        return None
    return candidate


def _validate_lsof_path(path: str) -> str | None:
    """Return ``path`` if it is an absolute, shell-safe filesystem path."""
    if not isinstance(path, str):
        return None
    candidate = path.strip()
    if not candidate or not candidate.startswith("/"):
        return None
    if len(candidate) > 4096:
        return None
    if any(ch in _PATH_FORBIDDEN_CHARS for ch in candidate):
        return None
    return candidate


def _validate_pid(pid: Any) -> int | None:
    """Return ``pid`` as a positive int, otherwise ``None``."""
    if pid is None:
        return None
    try:
        ivalue = int(pid)
    except (TypeError, ValueError):
        return None
    if ivalue <= 0:
        return None
    return ivalue


def _validate_journal_since(since: str) -> str | None:
    """Return ``since`` if it matches the limited charset accepted upstream."""
    if not isinstance(since, str):
        return None
    candidate = since.strip()
    if not candidate:
        return None
    if not _JOURNAL_SINCE_RE.match(candidate):
        return None
    return candidate


# ---------------------------------------------------------------------------
# Parsers (pure functions, easy to unit-test)
# ---------------------------------------------------------------------------


def _parse_ps_output(text: str) -> list[dict[str, Any]]:
    """Parse ``ps -eo pid,user,pcpu,pmem,etime,comm,args`` output.

    The first line is the header and is dropped. The remaining lines are
    split on whitespace for the first six columns; everything after that
    is treated as the full command line so it is preserved verbatim.
    """
    rows: list[dict[str, Any]] = []
    for idx, raw_line in enumerate(text.splitlines()):
        if idx == 0:
            # Header line emitted by ``ps`` - skip it.
            continue
        line = raw_line.rstrip()
        if not line:
            continue
        parts = line.split(None, 6)
        if len(parts) < 7:
            continue
        pid_str, user, pcpu, pmem, etime, comm, args = parts
        try:
            pid_int = int(pid_str)
        except ValueError:
            continue
        rows.append(
            {
                "pid": pid_int,
                "user": user,
                "cpu_percent": _safe_float(pcpu),
                "mem_percent": _safe_float(pmem),
                "elapsed": etime,
                "comm": comm,
                "command": args,
            }
        )
    return rows


def _parse_ss_output(text: str) -> list[dict[str, Any]]:
    """Parse ``ss -H -tunap`` output into structured socket records.

    Output columns: ``Netid State Recv-Q Send-Q LocalAddress:Port
    PeerAddress:Port [users:(...)]``. The optional last column (process
    info) is preserved as a raw string when present so the caller sees the
    same text ``ss`` would have shown.
    """
    rows: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        # ``ss -H`` should suppress the header; defensively skip it anyway.
        if line.lstrip().startswith(("Netid", "State")):
            continue
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        netid, state, recvq, sendq, local, peer = parts[:6]
        process = parts[6] if len(parts) > 6 else ""
        rows.append(
            {
                "protocol": netid,
                "state": state,
                "recv_q": _safe_int(recvq),
                "send_q": _safe_int(sendq),
                "local_address": local,
                "peer_address": peer,
                "process": process,
            }
        )
    return rows


def _parse_netstat_output(text: str) -> list[dict[str, Any]]:
    """Parse ``netstat -tunap`` output as a fallback when ``ss`` is missing.

    Skips banner / header lines and only emits records that look like real
    socket rows (i.e. start with a known protocol token).
    """
    rows: list[dict[str, Any]] = []
    valid_protocols = {"tcp", "tcp6", "udp", "udp6", "raw", "raw6"}
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        head = line.split(None, 1)[0].lower()
        if head not in valid_protocols:
            continue
        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        # netstat columns: Proto Recv-Q Send-Q LocalAddress ForeignAddress State [PID/Program]
        proto, recvq, sendq, local, foreign, state = parts[:6]
        process = parts[6] if len(parts) > 6 else ""
        rows.append(
            {
                "protocol": proto,
                "state": state,
                "recv_q": _safe_int(recvq),
                "send_q": _safe_int(sendq),
                "local_address": local,
                "peer_address": foreign,
                "process": process,
            }
        )
    return rows


def _parse_lsof_output(text: str) -> list[dict[str, Any]]:
    """Parse default ``lsof -nP`` output into structured records.

    Header line: ``COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME``.
    The NAME column may itself contain spaces so we split on at most 9
    columns and join the rest.
    """
    rows: list[dict[str, Any]] = []
    for idx, raw_line in enumerate(text.splitlines()):
        if idx == 0:
            continue
        line = raw_line.rstrip()
        if not line:
            continue
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        command, pid_str, user, fd, type_, device, size_off, node, name = parts
        rows.append(
            {
                "command": command,
                "pid": _safe_int(pid_str),
                "user": user,
                "fd": fd,
                "type": type_,
                "device": device,
                "size_or_offset": size_off,
                "node": node,
                "name": name,
            }
        )
    return rows


def _parse_df_output(text: str) -> list[dict[str, Any]]:
    """Parse ``df -P -k`` output into structured rows.

    Columns: ``Filesystem 1024-blocks Used Available Capacity Mounted-on``.
    All sizes are converted from kilobytes to bytes so downstream consumers
    do not have to know the ``-k`` flag was used.
    """
    rows: list[dict[str, Any]] = []
    for idx, raw_line in enumerate(text.splitlines()):
        if idx == 0:
            continue
        line = raw_line.rstrip()
        if not line:
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        filesystem, blocks, used, avail, capacity, mountpoint = parts
        rows.append(
            {
                "filesystem": filesystem,
                "size_bytes": _safe_int(blocks) * 1024,
                "used_bytes": _safe_int(used) * 1024,
                "available_bytes": _safe_int(avail) * 1024,
                "use_percent": capacity,
                "mountpoint": mountpoint,
            }
        )
    return rows


def _parse_meminfo(text: str) -> dict[str, int]:
    """Parse ``/proc/meminfo`` into a ``{key: bytes}`` map.

    Linux exposes values in kilobytes ("kB"); the trailing unit is stripped
    and the integer is multiplied by 1024 so the consumer always sees
    bytes. Unknown / malformed lines are skipped silently.
    """
    out: dict[str, int] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, _, rest = line.partition(":")
        rest = rest.strip()
        # Typical line: ``MemTotal:        16297588 kB``
        tokens = rest.split()
        if not tokens:
            continue
        value = _safe_int(tokens[0])
        if len(tokens) >= 2 and tokens[1].lower() == "kb":
            value *= 1024
        out[key.strip()] = value
    return out


def _parse_loadavg(text: str) -> dict[str, Any]:
    """Parse ``/proc/loadavg`` content into a structured dict."""
    parts = text.strip().split()
    if len(parts) < 3:
        return {}
    return {
        "load_1m": _safe_float(parts[0]),
        "load_5m": _safe_float(parts[1]),
        "load_15m": _safe_float(parts[2]),
        # ``running/total`` field present in /proc/loadavg
        "tasks": parts[3] if len(parts) >= 4 else "",
        "last_pid": _safe_int(parts[4]) if len(parts) >= 5 else 0,
    }


def _parse_systemctl_status(text: str) -> dict[str, Any]:
    """Extract a few well-known fields from ``systemctl status`` output.

    We only pull stable summary lines; the full text is also returned so
    a UI can render it verbatim. Missing fields collapse to empty strings
    so downstream code can rely on the keys always being present.
    """
    parsed: dict[str, Any] = {
        "loaded": "",
        "active": "",
        "main_pid": "",
        "tasks": "",
        "memory": "",
        "cgroup": "",
        "raw": text,
    }
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("Loaded:"):
            parsed["loaded"] = line[len("Loaded:"):].strip()
        elif line.startswith("Active:"):
            parsed["active"] = line[len("Active:"):].strip()
        elif line.startswith("Main PID:"):
            parsed["main_pid"] = line[len("Main PID:"):].strip()
        elif line.startswith("Tasks:"):
            parsed["tasks"] = line[len("Tasks:"):].strip()
        elif line.startswith("Memory:"):
            parsed["memory"] = line[len("Memory:"):].strip()
        elif line.startswith("CGroup:"):
            parsed["cgroup"] = line[len("CGroup:"):].strip()
    return parsed


# ---------------------------------------------------------------------------
# Tiny numeric helpers - never raise
# ---------------------------------------------------------------------------


def _safe_int(value: str) -> int:
    """Best-effort int conversion that returns 0 on failure."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: str) -> float:
    """Best-effort float conversion that returns 0.0 on failure."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _format_bytes(num_bytes: int) -> str:
    """Render a byte count as a short human-readable string (GiB / MiB)."""
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    size = float(num_bytes)
    idx = 0
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.1f} {units[idx]}"


def _cpu_count() -> int:
    """Return the number of online CPUs (1 when undetectable)."""
    # Prefer ``os.cpu_count`` to avoid spawning a subprocess.
    import os as _os

    count = _os.cpu_count()
    return count if count and count > 0 else 1


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------


def get_process_list(top_n: int = DEFAULT_PROCESS_LIMIT) -> dict[str, Any]:
    """Snapshot the top ``top_n`` processes sorted by CPU usage descending.

    Uses ``ps -eo pid,user,pcpu,pmem,etime,comm,args``. Sorting happens
    in Python (rather than ``ps --sort``) so the implementation also
    works on older or stripped-down ``ps`` builds.
    """
    tool = "get_process_list"
    limit = _clamp(top_n, default=DEFAULT_PROCESS_LIMIT, min_value=1, max_value=MAX_PROCESS_LIMIT)

    if _which("ps") is None:
        return _err(
            tool,
            "ps binary is not installed; cannot enumerate processes",
            "tool_unavailable",
        )

    rc, stdout, stderr, run_error = _run_command(
        ["ps", "-eo", "pid,user,pcpu,pmem,etime,comm,args"],
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )
    if run_error == "command_not_found":
        return _err(tool, "ps binary is not installed", "tool_unavailable")
    if run_error == "timeout":
        return _err(tool, f"ps timed out after {DEFAULT_TIMEOUT_SECONDS:.0f}s", "timeout")
    if run_error is not None or rc != 0:
        return _err(
            tool,
            f"ps exited with code {rc}: {stderr.strip()[:200]}",
            "command_failed",
        )

    rows = _parse_ps_output(stdout)
    rows.sort(key=lambda row: row.get("cpu_percent", 0.0), reverse=True)
    sample_total = len(rows)
    rows = rows[:limit]
    summary = f"top {len(rows)} process(es) by CPU (sampled {sample_total} total)"
    return _ok(tool, rows, summary)


def get_network_sockets(
    state: str = "all",
    top_n: int = DEFAULT_SOCKET_LIMIT,
) -> dict[str, Any]:
    """List active network sockets.

    Prefers ``ss`` (iproute2). Falls back to ``netstat`` automatically when
    ``ss`` is not installed. ``state`` is currently informational only -
    we always pass ``-a`` (all) and let the caller filter on the parsed
    fields - but the parameter is accepted for forward compatibility.
    """
    tool = "get_network_sockets"
    limit = _clamp(
        top_n,
        default=DEFAULT_SOCKET_LIMIT,
        min_value=1,
        max_value=MAX_SOCKET_LIMIT,
    )

    if _which("ss") is not None:
        rc, stdout, stderr, run_error = _run_command(
            ["ss", "-H", "-tunap"],
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        if run_error == "timeout":
            return _err(tool, f"ss timed out after {DEFAULT_TIMEOUT_SECONDS:.0f}s", "timeout")
        if run_error is None and rc == 0:
            rows = _parse_ss_output(stdout)
            sample_total = len(rows)
            rows = rows[:limit]
            return _ok(
                tool,
                {"backend": "ss", "state_filter": state, "sockets": rows},
                f"{len(rows)} socket(s) via ss (sampled {sample_total} total)",
            )
        # Otherwise fall through to netstat as a best-effort fallback.

    if _which("netstat") is not None:
        rc, stdout, stderr, run_error = _run_command(
            ["netstat", "-tunap"],
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        if run_error == "timeout":
            return _err(tool, f"netstat timed out after {DEFAULT_TIMEOUT_SECONDS:.0f}s", "timeout")
        if run_error is not None or rc != 0:
            return _err(
                tool,
                f"netstat exited with code {rc}: {stderr.strip()[:200]}",
                "command_failed",
            )
        rows = _parse_netstat_output(stdout)
        sample_total = len(rows)
        rows = rows[:limit]
        return _ok(
            tool,
            {"backend": "netstat", "state_filter": state, "sockets": rows},
            f"{len(rows)} socket(s) via netstat (sampled {sample_total} total)",
        )

    return _err(
        tool,
        "neither ss nor netstat is installed; cannot enumerate sockets",
        "tool_unavailable",
    )


def get_open_files(
    path: str | None = None,
    pid: int | None = None,
    top_n: int = DEFAULT_OPEN_FILES_LIMIT,
) -> dict[str, Any]:
    """List open file descriptors via ``lsof -nP``.

    At most one of ``path`` / ``pid`` should be supplied. When both are
    omitted the result is a system-wide snapshot capped at ``top_n``
    entries to keep the response bounded.
    """
    tool = "get_open_files"
    limit = _clamp(
        top_n,
        default=DEFAULT_OPEN_FILES_LIMIT,
        min_value=1,
        max_value=MAX_OPEN_FILES_LIMIT,
    )

    if _which("lsof") is None:
        return _err(
            tool,
            "lsof is not installed; cannot enumerate open files",
            "tool_unavailable",
        )

    argv: list[str] = ["lsof", "-nP"]
    target_desc = "all processes"

    if pid is not None:
        validated_pid = _validate_pid(pid)
        if validated_pid is None:
            return _err(tool, f"invalid pid: {pid!r}", "invalid_argument")
        argv.extend(["-p", str(validated_pid)])
        target_desc = f"pid={validated_pid}"

    if path is not None:
        validated_path = _validate_lsof_path(path)
        if validated_path is None:
            return _err(
                tool,
                f"invalid path argument: {path!r}",
                "invalid_argument",
            )
        # ``--`` ensures lsof does not try to interpret the path as a flag.
        argv.extend(["--", validated_path])
        target_desc = f"path={validated_path}" if pid is None else f"{target_desc}, path={validated_path}"

    rc, stdout, stderr, run_error = _run_command(
        argv,
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )
    if run_error == "command_not_found":
        return _err(tool, "lsof binary is not installed", "tool_unavailable")
    if run_error == "timeout":
        return _err(tool, f"lsof timed out after {DEFAULT_TIMEOUT_SECONDS:.0f}s", "timeout")
    # ``lsof`` may exit 1 when filtering matches nothing while still emitting
    # a usable header - treat that as a soft success with empty rows.
    if run_error is not None or rc not in (0, 1):
        return _err(
            tool,
            f"lsof exited with code {rc}: {stderr.strip()[:200]}",
            "command_failed",
        )

    rows = _parse_lsof_output(stdout)
    sample_total = len(rows)
    rows = rows[:limit]
    return _ok(
        tool,
        {"target": target_desc, "files": rows},
        f"{len(rows)} open file handle(s) for {target_desc} (sampled {sample_total} total)",
    )


def get_system_logs(
    unit: str | None = None,
    lines: int = DEFAULT_LOG_LINES,
    since: str | None = None,
) -> dict[str, Any]:
    """Tail recent journal entries via ``journalctl``.

    ``unit`` filters by systemd unit (e.g. ``sshd.service``). ``since``
    accepts journalctl's relative or absolute timestamp syntax (e.g.
    ``"1 hour ago"``). Both are validated against a strict charset so
    they cannot inject extra arguments even though we use argv form.
    """
    tool = "get_system_logs"
    line_count = _clamp(
        lines,
        default=DEFAULT_LOG_LINES,
        min_value=1,
        max_value=MAX_LOG_LINES,
    )

    if _which("journalctl") is None:
        return _err(
            tool,
            "journalctl is not installed; cannot read system logs",
            "tool_unavailable",
        )

    argv: list[str] = [
        "journalctl",
        "--no-pager",
        "-o",
        "short-iso",
        "-n",
        str(line_count),
    ]

    if unit is not None:
        validated_unit = _validate_service_name(unit)
        if validated_unit is None:
            return _err(
                tool,
                f"invalid unit name: {unit!r}",
                "invalid_argument",
            )
        argv.extend(["-u", validated_unit])

    if since is not None:
        validated_since = _validate_journal_since(since)
        if validated_since is None:
            return _err(
                tool,
                f"invalid since expression: {since!r}",
                "invalid_argument",
            )
        argv.extend(["--since", validated_since])

    rc, stdout, stderr, run_error = _run_command(argv, timeout=LOG_TIMEOUT_SECONDS)
    if run_error == "command_not_found":
        return _err(tool, "journalctl binary is not installed", "tool_unavailable")
    if run_error == "timeout":
        return _err(tool, f"journalctl timed out after {LOG_TIMEOUT_SECONDS:.0f}s", "timeout")
    if run_error is not None or rc != 0:
        return _err(
            tool,
            f"journalctl exited with code {rc}: {stderr.strip()[:200]}",
            "command_failed",
        )

    log_lines = [line for line in stdout.splitlines() if line]
    return _ok(
        tool,
        {
            "unit": unit,
            "since": since,
            "lines_requested": line_count,
            "entries": log_lines,
        },
        f"{len(log_lines)} log entry(ies) returned",
    )


def get_disk_usage() -> dict[str, Any]:
    """Report disk usage for every mounted filesystem.

    Uses ``df -P -k`` (POSIX-portable) so output is identical across most
    Linux distributions including Kylin V10.
    """
    tool = "get_disk_usage"

    if _which("df") is None:
        return _err(
            tool,
            "df is not installed; cannot enumerate disk usage",
            "tool_unavailable",
        )

    rc, stdout, stderr, run_error = _run_command(
        ["df", "-P", "-k"],
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )
    if run_error == "command_not_found":
        return _err(tool, "df binary is not installed", "tool_unavailable")
    if run_error == "timeout":
        return _err(tool, f"df timed out after {DEFAULT_TIMEOUT_SECONDS:.0f}s", "timeout")
    if run_error is not None or rc != 0:
        return _err(
            tool,
            f"df exited with code {rc}: {stderr.strip()[:200]}",
            "command_failed",
        )

    rows = _parse_df_output(stdout)
    return _ok(
        tool,
        rows,
        f"{len(rows)} filesystem(s) reported",
    )


def get_memory_status() -> dict[str, Any]:
    """Report memory and swap usage.

    Prefers ``/proc/meminfo`` because it is a small text file that does
    not require spawning a subprocess. Falls back to ``free -k`` when
    ``/proc/meminfo`` is unavailable (non-Linux hosts).
    """
    tool = "get_memory_status"
    meminfo_path = Path("/proc/meminfo")

    if meminfo_path.exists():
        try:
            text = meminfo_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return _err(
                tool,
                f"cannot read /proc/meminfo: {exc}",
                "command_failed",
            )
        if len(text.encode("utf-8")) > MAX_STDOUT_BYTES:
            text = text[:MAX_STDOUT_BYTES]
        meminfo = _parse_meminfo(text)
        if not meminfo:
            return _err(
                tool,
                "/proc/meminfo could not be parsed",
                "command_failed",
            )
        total = meminfo.get("MemTotal", 0)
        avail = meminfo.get("MemAvailable", 0)
        free = meminfo.get("MemFree", 0)
        swap_total = meminfo.get("SwapTotal", 0)
        swap_free = meminfo.get("SwapFree", 0)
        data = {
            "source": "/proc/meminfo",
            "total_bytes": total,
            "available_bytes": avail,
            "free_bytes": free,
            "buffers_bytes": meminfo.get("Buffers", 0),
            "cached_bytes": meminfo.get("Cached", 0),
            "swap_total_bytes": swap_total,
            "swap_free_bytes": swap_free,
            "raw": meminfo,
        }
        summary = (
            f"memory: {_format_bytes(total)} total, "
            f"{_format_bytes(avail)} available; "
            f"swap {_format_bytes(swap_total - swap_free)} used / {_format_bytes(swap_total)}"
        )
        return _ok(tool, data, summary)

    if _which("free") is None:
        return _err(
            tool,
            "/proc/meminfo missing and free is not installed",
            "tool_unavailable",
        )

    rc, stdout, stderr, run_error = _run_command(
        ["free", "-k"],
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )
    if run_error == "command_not_found":
        return _err(tool, "free binary is not installed", "tool_unavailable")
    if run_error == "timeout":
        return _err(tool, f"free timed out after {DEFAULT_TIMEOUT_SECONDS:.0f}s", "timeout")
    if run_error is not None or rc != 0:
        return _err(
            tool,
            f"free exited with code {rc}: {stderr.strip()[:200]}",
            "command_failed",
        )
    return _ok(
        tool,
        {"source": "free", "raw_text": stdout},
        "raw `free -k` output (parsing not implemented for fallback path)",
    )


def get_cpu_load() -> dict[str, Any]:
    """Report 1m / 5m / 15m load averages and per-CPU normalization.

    Reads ``/proc/loadavg`` directly. On non-Linux hosts the file is
    missing and a structured ``tool_unavailable`` envelope is returned
    instead of crashing.
    """
    tool = "get_cpu_load"
    loadavg_path = Path("/proc/loadavg")
    if not loadavg_path.exists():
        return _err(
            tool,
            "/proc/loadavg is not available on this host",
            "tool_unavailable",
        )
    try:
        text = loadavg_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _err(
            tool,
            f"cannot read /proc/loadavg: {exc}",
            "command_failed",
        )

    parsed = _parse_loadavg(text)
    if not parsed:
        return _err(
            tool,
            "/proc/loadavg returned an unexpected format",
            "command_failed",
        )

    cpu_count = _cpu_count()
    load_1m = parsed.get("load_1m", 0.0)
    per_cpu_pct = (load_1m / cpu_count) * 100.0 if cpu_count else 0.0
    data = {
        "load_1m": parsed["load_1m"],
        "load_5m": parsed["load_5m"],
        "load_15m": parsed["load_15m"],
        "tasks": parsed["tasks"],
        "last_pid": parsed["last_pid"],
        "cpu_count": cpu_count,
        "load_1m_per_cpu_percent": round(per_cpu_pct, 2),
    }
    summary = (
        f"load: {data['load_1m']}/{data['load_5m']}/{data['load_15m']} "
        f"on {cpu_count} CPU(s) ({data['load_1m_per_cpu_percent']}% per core)"
    )
    return _ok(tool, data, summary)


def get_uptime() -> dict[str, Any]:
    """Report system uptime, idle time and a human-readable summary.

    Two sources are attempted in order:

    1. ``/proc/uptime`` for the canonical numeric values (uptime seconds
       and idle seconds across all CPUs).
    2. ``uptime -p`` (pretty form, e.g. ``up 3 hours, 12 minutes``) for
       the human-readable summary. Falls back to a self-formatted
       summary when the ``uptime`` binary is missing.

    The envelope shape matches the other tools in this module so the
    MCP layer never has to special-case it.
    """
    tool = "get_uptime"
    uptime_path = Path("/proc/uptime")
    if not uptime_path.exists():
        return _err(
            tool,
            "/proc/uptime is not available on this host",
            "tool_unavailable",
        )
    try:
        text = uptime_path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError as exc:
        return _err(
            tool,
            f"cannot read /proc/uptime: {exc}",
            "command_failed",
        )
    parts = text.split()
    try:
        uptime_seconds = float(parts[0]) if parts else 0.0
        idle_seconds = float(parts[1]) if len(parts) > 1 else 0.0
    except ValueError:
        return _err(
            tool,
            "/proc/uptime returned an unexpected format",
            "command_failed",
        )

    pretty: Optional[str] = None
    if _which("uptime") is not None:
        rc, stdout, _stderr, err_code = _run_command(
            ["uptime", "-p"],
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        if err_code is None and rc == 0:
            line = stdout.strip().splitlines()[0] if stdout.strip() else ""
            if line:
                pretty = line

    if pretty is None:
        pretty = _format_uptime_pretty(uptime_seconds)

    data = {
        "uptime_seconds": uptime_seconds,
        "idle_seconds": idle_seconds,
        "uptime_human": pretty,
    }
    summary = f"system uptime: {pretty}"
    return _ok(tool, data, summary)


def _format_uptime_pretty(seconds: float) -> str:
    """Render an uptime float as ``Nd Nh Nm`` for the no-uptime-binary path."""
    total = max(0, int(seconds))
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")
    return "up " + " ".join(parts)


def get_service_status(service: str) -> dict[str, Any]:
    """Report systemd service status using ``systemctl``.

    Two read-only invocations are made: ``systemctl is-active`` to obtain
    a single-token state and ``systemctl status --no-pager`` to obtain a
    short summary plus the most recent log lines.
    """
    tool = "get_service_status"

    validated = _validate_service_name(service)
    if validated is None:
        return _err(
            tool,
            f"invalid service name: {service!r}",
            "invalid_argument",
        )

    if _which("systemctl") is None:
        return _err(
            tool,
            "systemctl is not installed; cannot query service status",
            "tool_unavailable",
        )

    # 1) ``is-active`` - returns a one-line token (active/inactive/failed/...).
    rc_active, stdout_active, _stderr_active, err_active = _run_command(
        ["systemctl", "is-active", validated],
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )
    if err_active == "command_not_found":
        return _err(tool, "systemctl binary is not installed", "tool_unavailable")
    if err_active == "timeout":
        return _err(
            tool,
            f"systemctl is-active timed out after {DEFAULT_TIMEOUT_SECONDS:.0f}s",
            "timeout",
        )
    # ``is-active`` returns non-zero when the unit is not active; that is
    # still a valid answer so we keep going.
    active_state = stdout_active.strip().splitlines()[0].strip() if stdout_active else "unknown"

    # 2) ``status`` - parsed for stable summary fields.
    rc_status, stdout_status, stderr_status, err_status = _run_command(
        [
            "systemctl",
            "status",
            validated,
            "--no-pager",
            "-l",
            "-n",
            str(DEFAULT_STATUS_TAIL_LINES),
        ],
        timeout=SERVICE_TIMEOUT_SECONDS,
    )
    if err_status == "timeout":
        return _err(
            tool,
            f"systemctl status timed out after {SERVICE_TIMEOUT_SECONDS:.0f}s",
            "timeout",
        )
    # ``systemctl status`` returns 3 for inactive services and 4 for
    # unknown units; both still produce informative output.
    if err_status is not None and err_status != "command_not_found" and rc_status not in (0, 1, 2, 3, 4):
        return _err(
            tool,
            f"systemctl status exited with code {rc_status}: {stderr_status.strip()[:200]}",
            "command_failed",
        )

    parsed = _parse_systemctl_status(stdout_status or "")
    data = {
        "service": validated,
        "active_state": active_state,
        "is_active_exit_code": rc_active,
        "status_exit_code": rc_status,
        "summary": {
            "loaded": parsed.get("loaded", ""),
            "active": parsed.get("active", ""),
            "main_pid": parsed.get("main_pid", ""),
            "tasks": parsed.get("tasks", ""),
            "memory": parsed.get("memory", ""),
            "cgroup": parsed.get("cgroup", ""),
        },
        "raw_status": parsed.get("raw", ""),
    }
    summary = f"service {validated!r} is {active_state}"
    return _ok(tool, data, summary)


# ---------------------------------------------------------------------------
# Public re-exports - kept tiny so server.py can ``from os_service import *``.
# ---------------------------------------------------------------------------

__all__ = [
    "get_process_list",
    "get_network_sockets",
    "get_open_files",
    "get_system_logs",
    "get_disk_usage",
    "get_memory_status",
    "get_cpu_load",
    "get_service_status",
    # Helpers exposed for unit tests
    "_envelope",
    "_parse_ps_output",
    "_parse_ss_output",
    "_parse_netstat_output",
    "_parse_lsof_output",
    "_parse_df_output",
    "_parse_meminfo",
    "_parse_loadavg",
    "_parse_systemctl_status",
    "_validate_service_name",
    "_validate_lsof_path",
    "_validate_pid",
    "_validate_journal_since",
]
