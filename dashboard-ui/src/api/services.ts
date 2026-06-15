import { apiGet, apiGetActuator } from "./client";
import { USE_MOCK_DATA } from "./config";
import { mockChainView, mockEvents, mockExecutions } from "../mock/data";
import type { ChainView, ExecutionRecord, SecurityEvent } from "../types";

export async function fetchEvents(): Promise<SecurityEvent[]> {
  if (USE_MOCK_DATA) {
    return mockEvents;
  }
  // defense-gateway returns either { items: [...] } or a raw array depending on
  // the API version; both shapes are handled here so we never silently drop data.
  const raw = await apiGet<unknown>("/api/events?page=0&size=50");
  if (Array.isArray(raw)) {
    return raw as SecurityEvent[];
  }
  if (raw && typeof raw === "object" && Array.isArray((raw as { items?: unknown }).items)) {
    return (raw as { items: SecurityEvent[] }).items;
  }
  return [];
}

// Fetch a single event by its numeric id (URL :id) and fall back to a search
// by eventId string when the numeric route 404s. This works around the
// mixed id / eventId convention in defense-gateway responses.
export async function fetchEventById(id: string): Promise<SecurityEvent> {
  if (USE_MOCK_DATA) {
    return mockEvents.find((e) => e.id === id || e.eventId === id) ?? mockEvents[0];
  }
  try {
    return await apiGet<SecurityEvent>(`/api/events/${encodeURIComponent(id)}`);
  } catch (err) {
    // Try the eventId-based fallback before bubbling the error up.
    try {
      return await apiGet<SecurityEvent>(
        `/api/events/by-event-id/${encodeURIComponent(id)}`,
      );
    } catch {
      throw err;
    }
  }
}

/**
 * Chain-view (per-event sequence diagram) is not yet served by any backend
 * route; the dashboard renders the static `mockChainView` shape until the
 * agent-brain `/workflow/chain/{eventId}` endpoint ships. Marked clearly as
 * MOCK-ONLY so callers don't assume backend authority.
 */
export async function fetchChainView(_eventId: string): Promise<ChainView> {
  return mockChainView;
}

// /api/executions is served by actuator-service (port 8081), NOT defense-gateway.
// The base URL is sourced from VITE_ACTUATOR_BASE_URL.
export async function fetchExecutions(): Promise<ExecutionRecord[]> {
  if (USE_MOCK_DATA) {
    return mockExecutions;
  }
  return apiGetActuator<ExecutionRecord[]>("/api/executions");
}

