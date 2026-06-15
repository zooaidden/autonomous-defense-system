#!/usr/bin/env bash
# =============================================================================
# Autonomous Defense System - Kylin / LoongArch stop script
# =============================================================================
#
# Stops the five services started by start-all.sh in REVERSE order so the
# UI goes down first and the back-end services last:
#
#   dashboard-ui -> agent-brain -> defense-gateway -> actuator-service ->
#   formal-verifier
#
# For each service, we first try the PID file written by start-all.sh.
# If it is missing or stale, we fall back to "kill the process bound to the
# expected TCP port" so leftover services from a previous boot are still
# cleaned up.
#
# Exit codes:
#   0 - all services either stopped successfully or were not running
#   1 - one or more services could not be stopped (still bound to the port
#       after the kill window)
#
# All comments and log lines are English. Never use `sudo` here.
# =============================================================================

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_PROJECT_ROOT="$(cd "${DEPLOY_DIR}/.." && pwd)"

# Source the same .env as start-all.sh (port overrides etc.).
ENV_CANDIDATES=(
  "${SCRIPT_DIR}/.env"
  "${DEFAULT_PROJECT_ROOT}/deploy/kylin/.env"
  "${DEFAULT_PROJECT_ROOT}/.env"
)
for f in "${ENV_CANDIDATES[@]}"; do
  if [[ -r "${f}" ]]; then
    # shellcheck disable=SC1090
    set -a; source "${f}"; set +a
    break
  fi
done

PROJECT_ROOT="${PROJECT_ROOT:-${DEFAULT_PROJECT_ROOT}}"
RUN_DIR="${SCRIPT_DIR}/run"
PID_DIR="${RUN_DIR}/pids"

DEFENSE_GATEWAY_PORT="${DEFENSE_GATEWAY_PORT:-8080}"
AGENT_BRAIN_PORT="${AGENT_BRAIN_PORT:-8001}"
FORMAL_VERIFIER_PORT="${FORMAL_VERIFIER_PORT:-8002}"
ACTUATOR_SERVICE_PORT="${ACTUATOR_SERVICE_PORT:-8081}"
DASHBOARD_UI_PORT="${DASHBOARD_UI_PORT:-5173}"

# How long to wait for SIGTERM to take effect before escalating to SIGKILL.
GRACEFUL_WAIT_SECONDS="${GRACEFUL_WAIT_SECONDS:-8}"

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_INFO='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_END='\033[0m'
else
  C_INFO=''; C_OK=''; C_WARN=''; C_ERR=''; C_END=''
fi

log()  { printf "%b[%s] %s%b\n" "${C_INFO}" "$(date '+%Y-%m-%d %H:%M:%S')" "$*" "${C_END}"; }
ok()   { printf "%b[%s] %s%b\n" "${C_OK}"   "$(date '+%Y-%m-%d %H:%M:%S')" "$*" "${C_END}"; }
warn() { printf "%b[%s] %s%b\n" "${C_WARN}" "$(date '+%Y-%m-%d %H:%M:%S')" "$*" "${C_END}"; }
err()  { printf "%b[%s] %s%b\n" "${C_ERR}"  "$(date '+%Y-%m-%d %H:%M:%S')" "$*" "${C_END}" >&2; }

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

# Returns 0 when a TCP port has any listener.
port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\.)${port}$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\.)${port}$"
  else
    (echo > "/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1
  fi
}

# Print the PIDs that listen on the given TCP port (best effort).
pids_on_port() {
  local port="$1" out=""
  if command -v ss >/dev/null 2>&1; then
    # parse "users:((\"java\",pid=12345,fd=...))"
    out=$(ss -tlnp 2>/dev/null | awk -v p=":${port}$" '
      $4 ~ p {
        if (match($0, /pid=[0-9]+/)) {
          s=substr($0, RSTART+4, RLENGTH-4);
          print s;
        }
      }')
  fi
  if [[ -z "${out}" ]] && command -v lsof >/dev/null 2>&1; then
    out=$(lsof -nP -t -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null || true)
  fi
  if [[ -z "${out}" ]] && command -v fuser >/dev/null 2>&1; then
    out=$(fuser -n tcp "${port}" 2>/dev/null | tr -s ' ' '\n' || true)
  fi
  printf '%s\n' "${out}" | awk 'NF>0 && $1 ~ /^[0-9]+$/'
}

# Send SIGTERM and wait, escalate to SIGKILL when needed.
graceful_kill() {
  local pid="$1" name="$2"
  if ! kill -0 "${pid}" >/dev/null 2>&1; then
    return 0
  fi
  log "  sending SIGTERM to ${name} pid=${pid}"
  kill -TERM "${pid}" >/dev/null 2>&1 || true
  local elapsed=0
  while (( elapsed < GRACEFUL_WAIT_SECONDS )); do
    kill -0 "${pid}" >/dev/null 2>&1 || { ok "  ${name} pid=${pid} exited"; return 0; }
    sleep 1
    elapsed=$(( elapsed + 1 ))
  done
  warn "  ${name} pid=${pid} still alive after ${GRACEFUL_WAIT_SECONDS}s; sending SIGKILL"
  kill -KILL "${pid}" >/dev/null 2>&1 || true
  sleep 1
  if kill -0 "${pid}" >/dev/null 2>&1; then
    err "  ${name} pid=${pid} did not die even after SIGKILL"
    return 1
  fi
  ok "  ${name} pid=${pid} killed"
}

# Stop a single service: try the PID file first, then fall back to port.
# Args: <name> <port>
stop_service() {
  local name="$1" port="$2"
  local pid_file="${PID_DIR}/${name}.pid"
  log "==> stopping ${name} (port ${port})"

  local stopped=0
  if [[ -f "${pid_file}" ]]; then
    local pid; pid="$(<"${pid_file}")"
    if [[ -n "${pid}" ]] && kill -0 "${pid}" >/dev/null 2>&1; then
      graceful_kill "${pid}" "${name}" && stopped=1
    else
      log "  pid file present but pid=${pid:-<empty>} is not alive"
    fi
    rm -f "${pid_file}"
  else
    log "  no pid file at ${pid_file}"
  fi

  # Belt-and-suspenders: anything still bound to the expected port?
  if port_in_use "${port}"; then
    log "  port ${port} still in use; attempting port-based kill"
    local extra; extra="$(pids_on_port "${port}")"
    if [[ -n "${extra}" ]]; then
      while IFS= read -r p; do
        [[ -z "${p}" ]] && continue
        graceful_kill "${p}" "${name}@${port}" || true
      done <<<"${extra}"
    else
      warn "  could not enumerate pids for port ${port} (need ss -p, lsof, or fuser)"
    fi
  fi

  if port_in_use "${port}"; then
    err "  ${name} (port ${port}) is STILL bound after stop attempts"
    return 1
  fi
  ok "  ${name} stopped"
  return 0
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
log "================================================================"
log " Autonomous Defense System :: stop"
log "================================================================"

failed=()
# Reverse of start order: UI -> agent-brain -> gateway -> actuator -> verifier
stop_service "dashboard-ui"     "${DASHBOARD_UI_PORT}"     || failed+=("dashboard-ui")
stop_service "agent-brain"      "${AGENT_BRAIN_PORT}"      || failed+=("agent-brain")
stop_service "defense-gateway"  "${DEFENSE_GATEWAY_PORT}"  || failed+=("defense-gateway")
stop_service "actuator-service" "${ACTUATOR_SERVICE_PORT}" || failed+=("actuator-service")
stop_service "formal-verifier"  "${FORMAL_VERIFIER_PORT}"  || failed+=("formal-verifier")

log ""
if (( ${#failed[@]} > 0 )); then
  err "the following services could not be fully stopped: ${failed[*]}"
  exit 1
fi
ok "all services stopped"
exit 0
