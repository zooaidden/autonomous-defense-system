#!/usr/bin/env bash
set -e

ROOT=/home/zhu/multiple-agent/autonomous-defense-system
REAL_ENV="$ROOT/.env.real"

if [ ! -f "$REAL_ENV" ]; then
	  echo "ERROR: $REAL_ENV not found. Refuse to start agent-brain in mock mode."
	    exit 1
fi

set -a
source "$REAL_ENV"
set +a

if [ -z "${AGENT_BRAIN_LLM_API_KEY:-}" ] && [ -z "${OPENAI_API_KEY:-}" ]; then
	  echo "ERROR: AGENT_BRAIN_LLM_API_KEY or OPENAI_API_KEY is required. Refuse to start in mock mode."
	    exit 1
fi

cd "$ROOT/agent-brain"
source .venv/bin/activate

export AGENT_BRAIN_FAILURE_MODE=strict
export AGENT_BRAIN_ROOT_POLICY=refuse
export WORKFLOW_GUARD_STRICT=true

export ENABLE_MCP=true
export ACTUATOR_MCP_GUARD_ENABLED=true

export MCP_TOPOLOGY_MODE=local
export MCP_POLICY_MODE=local
export MCP_OS_MODE=local

export TOPOLOGY_MCP_SERVER_PATH=$ROOT/mcp-servers/topology-mcp-server
export POLICY_MCP_SERVER_PATH=$ROOT/mcp-servers/policy-mcp-server
export OS_MCP_SERVER_PATH=$ROOT/mcp-servers/os-mcp-server

export FORMAL_VERIFIER_BASE_URL=http://localhost:8002
export ACTUATOR_SERVICE_BASE_URL=http://localhost:8081
export AGENT_BRAIN_CORS_ORIGINS=http://192.168.127.138:5173,http://localhost:5173

echo "Starting agent-brain with real LLM:"
echo "  model=${AGENT_BRAIN_LLM_MODEL:-${OPENAI_MODEL:-unknown}}"
echo "  base=${AGENT_BRAIN_LLM_BASE_URL:-${OPENAI_BASE_URL:-https://api.openai.com/v1}}"

python -m uvicorn agent_brain.main:app --host 0.0.0.0 --port 8001
