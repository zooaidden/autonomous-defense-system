import { AGENT_BRAIN_BASE_URL } from "./config";
import type { OpsAuditReplay, OpsChatResponse } from "../types/ops";

// Thin client around the agent-brain OPS API. All errors surface as Error
// instances so callers can render them via try/catch.

export interface OpsChatRequestPayload {
  instruction: string;
}

const JSON_HEADERS = { "Content-Type": "application/json" } as const;

async function parseError(res: Response): Promise<string> {
  try {
    const data = (await res.json()) as { detail?: string; message?: string };
    return data.detail ?? data.message ?? `${res.status} ${res.statusText}`;
  } catch {
    return `${res.status} ${res.statusText}`;
  }
}

export async function postOpsChat(
  payload: OpsChatRequestPayload,
  baseUrl: string = AGENT_BRAIN_BASE_URL,
): Promise<OpsChatResponse> {
  const res = await fetch(`${baseUrl.replace(/\/$/, "")}/ops/chat`, {
    method: "POST",
    headers: JSON_HEADERS,
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(await parseError(res));
  return (await res.json()) as OpsChatResponse;
}

export async function getOpsAudit(
  requestId: string,
  baseUrl: string = AGENT_BRAIN_BASE_URL,
): Promise<OpsAuditReplay> {
  const res = await fetch(
    `${baseUrl.replace(/\/$/, "")}/ops/audit/${encodeURIComponent(requestId)}`,
  );
  if (!res.ok) throw new Error(await parseError(res));
  return (await res.json()) as OpsAuditReplay;
}
