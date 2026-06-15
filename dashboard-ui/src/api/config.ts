// Resolve API base URLs from Vite env.
//
// Three distinct services, three env vars - never collapse them:
//   * VITE_API_BASE_URL         defense-gateway (Java)   -> /api/events, /api/health
//   * VITE_AGENT_BRAIN_BASE_URL agent-brain (Python)     -> /workflow/run, /ops/chat,
//                                                          /system/status, /audit/{id}, /health
//   * VITE_ACTUATOR_BASE_URL    actuator-service (Java)  -> /api/executions, /api/strategies/*
//
// VITE_AGENT_BRAIN_URL is kept as a legacy alias for the agent-brain base.
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8080";

export const AGENT_BRAIN_URL =
  import.meta.env.VITE_AGENT_BRAIN_BASE_URL ??
  import.meta.env.VITE_AGENT_BRAIN_URL ??
  "http://localhost:8001";

// Convenience alias - some new modules read this name explicitly.
export const AGENT_BRAIN_BASE_URL = AGENT_BRAIN_URL;

// actuator-service provides /api/executions (in-memory persistence, demo-only)
// and /api/strategies/{id}/rollback. Defense-gateway must NOT serve these.
export const ACTUATOR_BASE_URL =
  import.meta.env.VITE_ACTUATOR_BASE_URL ?? "http://localhost:8081";

// Default to live integration; flip to mock only for offline demo screenshots.
export const USE_MOCK_DATA = (import.meta.env.VITE_USE_MOCK ?? "false") === "true";
