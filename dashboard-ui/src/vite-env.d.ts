/// <reference types="vite/client" />

// Project-specific Vite env vars consumed by src/api/config.ts.
//
// Real-integration defaults:
//   VITE_USE_MOCK              -> "false"
//   VITE_API_BASE_URL          -> http://localhost:8080   (defense-gateway: /api/events)
//   VITE_AGENT_BRAIN_BASE_URL  -> http://localhost:8001   (agent-brain: /workflow/run, /ops/chat,
//                                                          /system/status, /audit/{id})
//   VITE_AGENT_BRAIN_URL       -> alias of VITE_AGENT_BRAIN_BASE_URL (legacy name)
//   VITE_ACTUATOR_BASE_URL     -> http://localhost:8081   (actuator-service: /api/executions,
//                                                          /api/strategies/*)
interface ImportMetaEnv {
  readonly VITE_USE_MOCK?: string;
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_AGENT_BRAIN_BASE_URL?: string;
  readonly VITE_AGENT_BRAIN_URL?: string;
  readonly VITE_ACTUATOR_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
