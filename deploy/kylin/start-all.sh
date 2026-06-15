#!/usr/bin/env bash
# =============================================================================
# Autonomous Defense System - Kylin / LoongArch boot script
# =============================================================================
#
# Boots the five core services in the recommended order:
#
#   1. formal-verifier   (Python/uvicorn,  port 8002)
#   2. actuator-service  (Java/Spring Boot, port 8081)
#   3. defense-gateway   (Java/Spring Boot, port 8080)
#   4. agent-brain       (Python/uvicorn,  port 8001)
#   5. dashboard-ui      (Node/Vite,       port 5173)
#
# os-mcp-server / topology-mcp-server / policy-mcp-server are NOT started
# here. They are loaded in-process by agent-brain when MCP_*_MODE=local
# (default) and spawned on demand via stdio when MCP_*_MODE=real.
#
# Each service is launched with `nohup ... &`, its PID is captured in
# deploy/kylin/run/pids/<service>.pid, and stdout/stderr go to
# deploy/kylin/run/logs/<service>.log.
#
# Exit codes:
#   0 - all services started (or were already up on their port)
#   1 - precondition failed (bad PROJECT_ROOT, missing JAR, missing venv, etc.)
#   2 - one or more services failed to come online within the readiness window
#
# Conventions:
#   * All comments and log lines are English.
#   * Defaults match docs/kylin-deployment.md and the env.example file.
#   * No service is started with `sudo`; run as a dedicated low-priv user.
# =============================================================================

set -u   # treat unset vars as errors (do NOT use -e: we want to keep going
         # past a failed sub-step and report it explicitly).
set -o pipefail

# -----------------------------------------------------------------------------
# Locate script dir and project root.
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_PROJECT_ROOT="$(cd "${DEPLOY_DIR}/.." && pwd)"

# Source .env if present (overrides defaults below). Allow either the
# scripts dir or the project root to host the .env file.
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
LOG_DIR="${RUN_DIR}/logs"
PID_DIR="${RUN_DIR}/pids"
mkdir -p "${LOG_DIR}" "${PID_DIR}"

# -----------------------------------------------------------------------------
# Defaults for ports, binaries, JARs, venvs.
# -----------------------------------------------------------------------------
DEFENSE_GATEWAY_PORT="${DEFENSE_GATEWAY_PORT:-8080}"
AGENT_BRAIN_PORT="${AGENT_BRAIN_PORT:-8001}"
FORMAL_VERIFIER_PORT="${FORMAL_VERIFIER_PORT:-8002}"
ACTUATOR_SERVICE_PORT="${ACTUATOR_SERVICE_PORT:-8081}"
DASHBOARD_UI_PORT="${DASHBOARD_UI_PORT:-5173}"

JAVA_BIN="${JAVA_BIN:-java}"
PYTHON_BIN="${PYTHON_BIN:-python3.11}"
NODE_BIN="${NODE_BIN:-node}"
NPM_BIN="${NPM_BIN:-npm}"

AGENT_BRAIN_VENV="${AGENT_BRAIN_VENV:-${PROJECT_ROOT}/agent-brain/.venv}"
FORMAL_VERIFIER_VENV="${FORMAL_VERIFIER_VENV:-${PROJECT_ROOT}/formal-verifier/.venv}"

DEFENSE_GATEWAY_DIR="${PROJECT_ROOT}/defense-gateway"
ACTUATOR_SERVICE_DIR="${PROJECT_ROOT}/actuator-service"
AGENT_BRAIN_DIR="${PROJECT_ROOT}/agent-brain"
FORMAL_VERIFIER_DIR="${PROJECT_ROOT}/formal-verifier"
DASHBOARD_UI_DIR="${PROJECT_ROOT}/dashboard-ui"

# How long to wait for each service to become ready, and how often to poll.
READINESS_TIMEOUT_SECONDS="${READINESS_TIMEOUT_SECONDS:-60}"
READINESS_INTERVAL_SECONDS="${READINESS_INTERVAL_SECONDS:-2}"

# -----------------------------------------------------------------------------
# Tiny logging helpers (no colors when stdout is not a tty).
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
# Generic helpers
# -----------------------------------------------------------------------------

# Returns 0 when something is listening on the given TCP port.
port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\.)${port}$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\.)${port}$"
  else
    # Last resort: try a TCP connect via /dev/tcp.
    (echo > "/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1
  fi
}

# Wait until either the port is bound OR a curl probe returns 200 on the URL.
# Args: <name> <port> <probe-url-or-empty> <timeout-sec>
wait_until_ready() {
  local name="$1" port="$2" url="$3" timeout="${4:-${READINESS_TIMEOUT_SECONDS}}"
  local elapsed=0
  while (( elapsed < timeout )); do
    if [[ -n "${url}" ]] && command -v curl >/dev/null 2>&1; then
      if curl -fsS -o /dev/null -m 2 "${url}"; then
        ok "${name} ready (HTTP probe ok at ${url}, ${elapsed}s)"
        return 0
      fi
    fi
    if port_in_use "${port}"; then
      ok "${name} ready (port ${port} bound, ${elapsed}s)"
      return 0
    fi
    sleep "${READINESS_INTERVAL_SECONDS}"
    elapsed=$(( elapsed + READINESS_INTERVAL_SECONDS ))
  done
  warn "${name} did NOT become ready within ${timeout}s; check ${LOG_DIR}/${name}.log"
  return 1
}

# Spawn a service in the background, redirecting both streams to a log file
# and capturing the PID in a pid file.
# Args: <name> <work_dir> <command> [args...]
spawn() {
  local name="$1"; shift
  local work_dir="$1"; shift
  local log_file="${LOG_DIR}/${name}.log"
  local pid_file="${PID_DIR}/${name}.pid"

  if [[ -f "${pid_file}" ]] && kill -0 "$(<"${pid_file}")" >/dev/null 2>&1; then
    warn "${name} already running (pid=$(<"${pid_file}")); skipping"
    return 0
  fi

  log "starting ${name} -> ${log_file}"
  log "  command: $*"
  (
    cd "${work_dir}" || exit 127
    nohup "$@" >"${log_file}" 2>&1 &
    echo $! >"${pid_file}"
  )
  sleep 1
  if [[ -f "${pid_file}" ]] && kill -0 "$(<"${pid_file}")" >/dev/null 2>&1; then
    ok "${name} pid=$(<"${pid_file}")"
    return 0
  fi
  err "${name} failed to fork; tail of ${log_file}:"
  tail -n 20 "${log_file}" >&2 || true
  return 1
}

# Resolve an executable inside a venv (fall back to system one when missing).
venv_python() {
  local venv="$1"
  if [[ -x "${venv}/bin/python" ]]; then
    printf '%s\n' "${venv}/bin/python"
  else
    printf '%s\n' "${PYTHON_BIN}"
  fi
}

# Find the first jar that matches a glob, return empty when nothing matches.
first_jar() {
  local glob="$1"
  local hit
  # shellcheck disable=SC2086
  hit=$(ls -1 ${glob} 2>/dev/null | head -n1 || true)
  printf '%s\n' "${hit}"
}

# -----------------------------------------------------------------------------
# Pre-flight checks
# -----------------------------------------------------------------------------
log "project root: ${PROJECT_ROOT}"
log "logs   dir : ${LOG_DIR}"
log "pids   dir : ${PID_DIR}"

[[ -d "${PROJECT_ROOT}" ]] || { err "PROJECT_ROOT '${PROJECT_ROOT}' does not exist"; exit 1; }

if ! command -v "${JAVA_BIN}" >/dev/null 2>&1; then
  warn "java binary '${JAVA_BIN}' not found on PATH; Java services will be skipped."
fi
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  warn "python binary '${PYTHON_BIN}' not found on PATH; agent-brain / formal-verifier will be skipped."
fi
if ! command -v "${NODE_BIN}" >/dev/null 2>&1 || ! command -v "${NPM_BIN}" >/dev/null 2>&1; then
  warn "node/npm not found on PATH; dashboard-ui will be skipped."
fi

# Resolve JAR paths - prefer pinned env value, else autodetect.
DEFENSE_GATEWAY_JAR="${DEFENSE_GATEWAY_JAR:-$(first_jar "${DEFENSE_GATEWAY_DIR}/target/defense-gateway-*.jar")}"
ACTUATOR_SERVICE_JAR="${ACTUATOR_SERVICE_JAR:-$(first_jar "${ACTUATOR_SERVICE_DIR}/target/actuator-service-*.jar")}"

# Propagate dashboard env vars into a Vite .env so VITE_* are honored when
# `npm run dev` boots. We rewrite this on every start so env.example changes
# always take effect.
write_dashboard_env() {
  local target="${DASHBOARD_UI_DIR}/.env"
  cat > "${target}" <<EOF
# Auto-generated by deploy/kylin/start-all.sh - do not edit by hand.
VITE_AGENT_BRAIN_BASE_URL=${VITE_AGENT_BRAIN_BASE_URL:-http://localhost:${AGENT_BRAIN_PORT}}
VITE_API_BASE_URL=${VITE_API_BASE_URL:-http://localhost:${DEFENSE_GATEWAY_PORT}}
VITE_USE_MOCK=${VITE_USE_MOCK:-false}
EOF
  log "wrote ${target}"
}

# -----------------------------------------------------------------------------
# Service launchers
# -----------------------------------------------------------------------------

start_formal_verifier() {
  log "==> formal-verifier (port ${FORMAL_VERIFIER_PORT})"
  if [[ ! -d "${FORMAL_VERIFIER_DIR}" ]]; then
    warn "skipping: ${FORMAL_VERIFIER_DIR} not found"
    return 1
  fi
  local py
  py="$(venv_python "${FORMAL_VERIFIER_VENV}")"
  if ! "${py}" -c 'import formal_verifier' >/dev/null 2>&1; then
    warn "formal_verifier package not installed in venv (${py}); run \`pip install -e .\` inside ${FORMAL_VERIFIER_DIR}"
  fi
  spawn "formal-verifier" "${FORMAL_VERIFIER_DIR}" \
    "${py}" -m uvicorn formal_verifier.main:app \
    --host 0.0.0.0 --port "${FORMAL_VERIFIER_PORT}" --no-access-log
  wait_until_ready "formal-verifier" "${FORMAL_VERIFIER_PORT}" \
    "http://127.0.0.1:${FORMAL_VERIFIER_PORT}/health" 30
}

start_actuator_service() {
  log "==> actuator-service (port ${ACTUATOR_SERVICE_PORT})"
  if [[ -z "${ACTUATOR_SERVICE_JAR}" || ! -f "${ACTUATOR_SERVICE_JAR}" ]]; then
    warn "skipping: actuator-service jar not built. Run: ./mvnw -pl actuator-service -am clean package -DskipTests"
    return 1
  fi
  spawn "actuator-service" "${ACTUATOR_SERVICE_DIR}" \
    "${JAVA_BIN}" -Dserver.port="${ACTUATOR_SERVICE_PORT}" -jar "${ACTUATOR_SERVICE_JAR}"
  wait_until_ready "actuator-service" "${ACTUATOR_SERVICE_PORT}" "" 60
}

start_defense_gateway() {
  log "==> defense-gateway (port ${DEFENSE_GATEWAY_PORT})"
  if [[ -z "${DEFENSE_GATEWAY_JAR}" || ! -f "${DEFENSE_GATEWAY_JAR}" ]]; then
    warn "skipping: defense-gateway jar not built. Run: ./mvnw -pl defense-gateway -am clean package -DskipTests"
    return 1
  fi
  spawn "defense-gateway" "${DEFENSE_GATEWAY_DIR}" \
    "${JAVA_BIN}" -Dserver.port="${DEFENSE_GATEWAY_PORT}" -jar "${DEFENSE_GATEWAY_JAR}"
  wait_until_ready "defense-gateway" "${DEFENSE_GATEWAY_PORT}" "" 60
}

start_agent_brain() {
  log "==> agent-brain (port ${AGENT_BRAIN_PORT})"
  if [[ ! -d "${AGENT_BRAIN_DIR}" ]]; then
    warn "skipping: ${AGENT_BRAIN_DIR} not found"
    return 1
  fi
  local py
  py="$(venv_python "${AGENT_BRAIN_VENV}")"
  if ! "${py}" -c 'import agent_brain' >/dev/null 2>&1; then
    warn "agent_brain package not installed in venv (${py}); run \`pip install -e .[mcp]\` inside ${AGENT_BRAIN_DIR}"
  fi
  spawn "agent-brain" "${AGENT_BRAIN_DIR}" \
    "${py}" -m uvicorn agent_brain.main:app \
    --host 0.0.0.0 --port "${AGENT_BRAIN_PORT}" --no-access-log
  wait_until_ready "agent-brain" "${AGENT_BRAIN_PORT}" \
    "http://127.0.0.1:${AGENT_BRAIN_PORT}/health" 45
}

start_dashboard_ui() {
  log "==> dashboard-ui (port ${DASHBOARD_UI_PORT})"
  if [[ ! -d "${DASHBOARD_UI_DIR}" ]]; then
    warn "skipping: ${DASHBOARD_UI_DIR} not found"
    return 1
  fi
  if [[ ! -d "${DASHBOARD_UI_DIR}/node_modules" ]]; then
    warn "node_modules missing - running 'npm ci' (this may take a while)..."
    (cd "${DASHBOARD_UI_DIR}" && "${NPM_BIN}" ci) || {
      err "npm ci failed; aborting dashboard-ui startup"
      return 1
    }
  fi
  write_dashboard_env
  spawn "dashboard-ui" "${DASHBOARD_UI_DIR}" \
    "${NPM_BIN}" run dev -- --host 0.0.0.0 --port "${DASHBOARD_UI_PORT}"
  wait_until_ready "dashboard-ui" "${DASHBOARD_UI_PORT}" "" 45
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
log "================================================================"
log " Autonomous Defense System :: Kylin / LoongArch boot"
log "================================================================"

failures=()
start_formal_verifier  || failures+=("formal-verifier")
start_actuator_service || failures+=("actuator-service")
start_defense_gateway  || failures+=("defense-gateway")
start_agent_brain      || failures+=("agent-brain")
start_dashboard_ui     || failures+=("dashboard-ui")

log ""
log "----------------------------------------------------------------"
log " Service summary"
log "----------------------------------------------------------------"
printf "  %-22s %-7s %-7s %s\n" "service" "port" "pid" "log"
for svc in formal-verifier actuator-service defense-gateway agent-brain dashboard-ui; do
  pid=""; [[ -f "${PID_DIR}/${svc}.pid" ]] && pid="$(<"${PID_DIR}/${svc}.pid")"
  case "${svc}" in
    formal-verifier)  port="${FORMAL_VERIFIER_PORT}"  ;;
    actuator-service) port="${ACTUATOR_SERVICE_PORT}" ;;
    defense-gateway)  port="${DEFENSE_GATEWAY_PORT}"  ;;
    agent-brain)      port="${AGENT_BRAIN_PORT}"      ;;
    dashboard-ui)     port="${DASHBOARD_UI_PORT}"     ;;
  esac
  printf "  %-22s %-7s %-7s %s\n" "${svc}" "${port}" "${pid:--}" "${LOG_DIR}/${svc}.log"
done
log "----------------------------------------------------------------"

if (( ${#failures[@]} > 0 )); then
  warn "the following services failed or were skipped: ${failures[*]}"
  log "tip: run \`bash deploy/kylin/check-health.sh\` after a few seconds to re-probe"
  exit 2
fi

ok "all services started. Open http://localhost:${DASHBOARD_UI_PORT} (dashboard) or http://localhost:${AGENT_BRAIN_PORT}/health"
exit 0
