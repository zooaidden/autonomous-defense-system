#!/usr/bin/env bash
# =============================================================================
# Autonomous Defense System - health probe
# =============================================================================
#
# Probes the five well-known ports of the deployment:
#
#     8080  defense-gateway
#     8001  agent-brain
#     8002  formal-verifier
#     8081  actuator-service
#     5173  dashboard-ui
#
# For each port we run two checks:
#
#   1) "port-bound"    - lightweight TCP listen check using ss / netstat /
#                        /dev/tcp depending on what is available.
#   2) "http-probe"    - curl against a sensible endpoint (e.g. /health,
#                        /actuator/health or /). When curl is missing we
#                        treat the port-bound check alone as a soft pass.
#
# Exit codes:
#   0 - every service answered with a successful HTTP probe (OR was at
#       least port-bound when curl is unavailable)
#   1 - one or more services failed both checks
#
# All comments and log lines are English.
# =============================================================================

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEFAULT_PROJECT_ROOT="$(cd "${DEPLOY_DIR}/.." && pwd)"

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

# Allow port overrides via env, default to spec values.
DEFENSE_GATEWAY_PORT="${DEFENSE_GATEWAY_PORT:-8080}"
AGENT_BRAIN_PORT="${AGENT_BRAIN_PORT:-8001}"
FORMAL_VERIFIER_PORT="${FORMAL_VERIFIER_PORT:-8002}"
ACTUATOR_SERVICE_PORT="${ACTUATOR_SERVICE_PORT:-8081}"
DASHBOARD_UI_PORT="${DASHBOARD_UI_PORT:-5173}"

CURL_TIMEOUT_SECONDS="${CURL_TIMEOUT_SECONDS:-3}"
HOST="${HEALTH_PROBE_HOST:-127.0.0.1}"

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_INFO='\033[1;36m'; C_OK='\033[1;32m'; C_WARN='\033[1;33m'; C_ERR='\033[1;31m'; C_END='\033[0m'
else
  C_INFO=''; C_OK=''; C_WARN=''; C_ERR=''; C_END=''
fi

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\.)${port}$"
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tln 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\.)${port}$"
  else
    (echo > "/dev/tcp/${HOST}/${port}") >/dev/null 2>&1
  fi
}

# Return the first URL that responds with HTTP 2xx/3xx/4xx (anything that
# means "process answered"). 5xx and connect failures are treated as down.
# Args: <url> [more urls...]
http_probe() {
  command -v curl >/dev/null 2>&1 || return 2
  local code
  for url in "$@"; do
    code=$(curl -fsS -o /dev/null -w "%{http_code}" -m "${CURL_TIMEOUT_SECONDS}" "${url}" 2>/dev/null || true)
    # curl returns empty code on connect/timeout failure
    if [[ -n "${code}" && "${code}" -ge 100 && "${code}" -lt 500 ]]; then
      printf '%s|%s\n' "${url}" "${code}"
      return 0
    fi
  done
  return 1
}

# Pretty status row.
# Args: <name> <port> <status> <detail>
print_row() {
  local name="$1" port="$2" status="$3" detail="$4"
  local color
  case "${status}" in
    OK)         color="${C_OK}"   ;;
    PORT-ONLY)  color="${C_WARN}" ;;
    DOWN)       color="${C_ERR}"  ;;
    *)          color="${C_INFO}" ;;
  esac
  printf "  %b%-10s%b  %-22s  port=%-5s  %s\n" "${color}" "${status}" "${C_END}" "${name}" "${port}" "${detail}"
}

# Probe a single service. Sets the global PROBE_OK=1 on success, 0 on failure.
# Args: <name> <port> <probe_url_1> [probe_url_2] ...
probe_service() {
  local name="$1"; shift
  local port="$1"; shift
  local urls=("$@")

  PROBE_OK=0
  if ! port_in_use "${port}"; then
    print_row "${name}" "${port}" "DOWN" "no listener"
    return 1
  fi

  local result
  if result="$(http_probe "${urls[@]}")"; then
    print_row "${name}" "${port}" "OK" "${result}"
    PROBE_OK=1
    return 0
  fi
  local rc=$?
  if [[ ${rc} -eq 2 ]]; then
    # No curl -> port-only is the best we can say.
    print_row "${name}" "${port}" "PORT-ONLY" "(curl missing)"
    PROBE_OK=1
    return 0
  fi
  print_row "${name}" "${port}" "DOWN" "port bound but no successful HTTP response on probes: $(IFS=, ; echo "${urls[*]}")"
  return 1
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
echo
echo "==================== health probe ===================="
echo " host=${HOST}  curl_timeout=${CURL_TIMEOUT_SECONDS}s"
echo "------------------------------------------------------"

failures=0

# Java services expose their app-level health under /api/health (Spring
# Boot actuator endpoints are NOT bundled by default in this project, so
# /actuator/health 404s by design). Python services expose /health.
probe_service "defense-gateway"  "${DEFENSE_GATEWAY_PORT}"  \
  "http://${HOST}:${DEFENSE_GATEWAY_PORT}/api/health" \
  "http://${HOST}:${DEFENSE_GATEWAY_PORT}/" \
  || failures=$(( failures + 1 ))

probe_service "agent-brain"      "${AGENT_BRAIN_PORT}"      \
  "http://${HOST}:${AGENT_BRAIN_PORT}/health" \
  "http://${HOST}:${AGENT_BRAIN_PORT}/" \
  || failures=$(( failures + 1 ))

probe_service "formal-verifier"  "${FORMAL_VERIFIER_PORT}"  \
  "http://${HOST}:${FORMAL_VERIFIER_PORT}/health" \
  "http://${HOST}:${FORMAL_VERIFIER_PORT}/" \
  || failures=$(( failures + 1 ))

probe_service "actuator-service" "${ACTUATOR_SERVICE_PORT}" \
  "http://${HOST}:${ACTUATOR_SERVICE_PORT}/api/health" \
  "http://${HOST}:${ACTUATOR_SERVICE_PORT}/" \
  || failures=$(( failures + 1 ))

probe_service "dashboard-ui"     "${DASHBOARD_UI_PORT}"     \
  "http://${HOST}:${DASHBOARD_UI_PORT}/" \
  || failures=$(( failures + 1 ))

echo "------------------------------------------------------"

# -----------------------------------------------------------------------------
# Kylin security subsystem probes (informational, non-fatal)
# -----------------------------------------------------------------------------
print_kylin_sec_row() {
  local name="$1" status="$2" detail="$3"
  local color
  case "${status}" in
    YES)  color="${C_OK}"   ;;
    NO)   color="${C_WARN}" ;;
    *)    color="${C_INFO}" ;;
  esac
  printf "  %b%-5s%b  %-30s  %s\n" "${color}" "${status}" "${C_END}" "${name}" "${detail}"
}

check_kylin_security() {
  # Only run on Linux; skip silently on other platforms.
  [[ "$(uname -s)" == "Linux" ]] || return 0

  echo "--- Kylin Security Subsystem ---"

  # KylinSec MAC
  if command -v kylinsec-status >/dev/null 2>&1; then
    local mode
    mode=$(kylinsec-status 2>/dev/null | head -1 || echo "unknown")
    print_kylin_sec_row "KylinSec MAC"      "YES" "${mode}"
  elif [[ -e /sys/kernel/security/kylinsec/enforce ]]; then
    print_kylin_sec_row "KylinSec MAC"      "YES" "$(cat /sys/kernel/security/kylinsec/enforce 2>/dev/null || echo '?')"
  else
    print_kylin_sec_row "KylinSec MAC"      "NO"  "not detected"
  fi

  # TCM
  if [[ -e /dev/tcm0 ]]; then
    print_kylin_sec_row "TCM device"        "YES" "/dev/tcm0 present"
  elif [[ -d /sys/class/tcm ]]; then
    print_kylin_sec_row "TCM device"        "YES" "/sys/class/tcm present"
  else
    print_kylin_sec_row "TCM device"         "NO"  "not detected"
  fi

  # IMA
  if [[ -e /sys/kernel/security/ima/policy ]]; then
    local policy_bytes
    policy_bytes=$(wc -c < /sys/kernel/security/ima/policy 2>/dev/null || echo 0)
    print_kylin_sec_row "IMA integrity"     "YES" "policy=${policy_bytes} bytes"
  else
    print_kylin_sec_row "IMA integrity"     "NO"  "not enabled"
  fi

  # auditd
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
      print_kylin_sec_row "auditd"           "YES" "active"
    else
      print_kylin_sec_row "auditd"           "NO"  "inactive or missing"
    fi
  fi

  # Kylin release
  if [[ -e /etc/kylin-release ]]; then
    print_kylin_sec_row "Kylin release"     "YES" "$(head -1 /etc/kylin-release 2>/dev/null || echo '?')"
  fi

  # CPU architecture
  local arch
  arch=$(uname -m 2>/dev/null || echo "unknown")
  print_kylin_sec_row "CPU architecture"   ""    "${arch}"

  echo "------------------------------------------------------"
}

check_kylin_security

if (( failures > 0 )); then
  printf " %bRESULT: %d service(s) DOWN%b\n" "${C_ERR}" "${failures}" "${C_END}"
  echo "======================================================"
  echo
  exit 1
fi
printf " %bRESULT: all services healthy%b\n" "${C_OK}" "${C_END}"
echo "======================================================"
echo
exit 0
