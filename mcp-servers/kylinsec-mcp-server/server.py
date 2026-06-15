"""FastMCP stdio server wrapping ``kylinsec_service`` for the real-mode transport.

When ``MCP_KYLINSEC_MODE=real``, agent-brain spawns this script as a
child process and communicates via the MCP stdio protocol.  All business
logic lives in ``kylinsec_service`` (zero MCP deps) so tests can import
it directly.
"""

from mcp.server.fastmcp import FastMCP

from kylinsec_service import (
    check_seccomp_arch,
    get_kernel_module_signatures,
    get_kylin_audit_policy,
    get_kylin_patch_level,
    get_kylinsec_status,
    get_tcm_pcrs,
    verify_binary_ima,
)

mcp = FastMCP("kylinsec-mcp-server")


@mcp.tool()
def get_kylinsec_status_tool() -> dict:
    """Query KylinSec MAC (Mandatory Access Control) runtime status.

    Returns the enforcement mode (enforcing/permissive/disabled) and
    policy version of the Kylin security framework. On non-Kylin hosts
    the tool returns ``{success: false, error: "tool_unavailable"}``.
    """
    return get_kylinsec_status()


@mcp.tool()
def get_tcm_pcrs_tool() -> dict:
    """Read TCM (Trusted Cryptography Module) PCR register values.

    TCM is the Chinese national-standard trusted computing module
    (analogous to TPM). PCR values form the basis of remote attestation
    and measured boot verification. Returns the raw PCR content and
    the TCM device path.
    """
    return get_tcm_pcrs()


@mcp.tool()
def verify_binary_ima_tool(path: str) -> dict:
    """Verify a binary file against the IMA runtime measurement log.

    Args:
        path: Absolute path to the binary to verify
            (e.g. ``/usr/bin/agent-brain``).

    Returns matching entries from the IMA log (found in
    ``/sys/kernel/security/ima/ascii_runtime_measurements``).
    """
    return verify_binary_ima(path)


@mcp.tool()
def get_kernel_module_signatures_tool() -> dict:
    """Enumerate loaded kernel modules and their signature status.

    On Kylin V11, kernel module signing is mandatory. This tool reports
    for every loaded module whether it carries a valid signature and who
    signed it. Unsigned modules are a strong indicator of tampering.
    """
    return get_kernel_module_signatures()


@mcp.tool()
def get_kylin_patch_level_tool() -> dict:
    """Report the Kylin release version, kernel version, and CPU architecture.

    Includes the rpm package version of ``kylin-release``, the
    ``/etc/kylin-release`` content, and platform metadata suitable for
    displaying the "Kylin V11 / LoongArch" badge on the dashboard.
    """
    return get_kylin_patch_level()


@mcp.tool()
def check_seccomp_arch_tool() -> dict:
    """Return the seccomp audit architecture identifier for the current CPU.

    seccomp BPF filters must use the correct syscall numbers for the
    host architecture. This tool maps ``uname -m`` to the corresponding
    ``AUDIT_ARCH_*`` constant so programmatic filter generation is
    always correct.
    """
    return check_seccomp_arch()


@mcp.tool()
def get_kylin_audit_policy_tool() -> dict:
    """Query the kernel audit subsystem's current rules and enabled state.

    Returns the output of ``auditctl -l`` and ``auditctl -s`` so
    operators can verify that the expected audit rules are active.
    """
    return get_kylin_audit_policy()


if __name__ == "__main__":
    mcp.run()
