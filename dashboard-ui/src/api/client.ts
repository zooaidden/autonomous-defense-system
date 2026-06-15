import { ACTUATOR_BASE_URL, AGENT_BRAIN_BASE_URL, API_BASE_URL } from "./config";

// Default to defense-gateway (events feed). Callers can pass an explicit
// baseUrl to retarget actuator-service or agent-brain.
export async function apiGet<T>(path: string, baseUrl: string = API_BASE_URL): Promise<T> {
  const response = await fetch(`${baseUrl}${path}`);
  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }
  const body = await response.json();
  return body.data ?? body;
}

// Convenience wrappers so service modules don't repeat the base-URL choice.
export function apiGetActuator<T>(path: string): Promise<T> {
  return apiGet<T>(path, ACTUATOR_BASE_URL);
}

export function apiGetAgentBrain<T>(path: string): Promise<T> {
  return apiGet<T>(path, AGENT_BRAIN_BASE_URL);
}

