import { AGENT_BRAIN_URL } from "./config";
import type { SecurityEvent } from "../types";
import type { WorkflowRunResult } from "../types/workflow";

/** Payload shape accepted by agent-brain POST /workflow/run */
export function buildWorkflowSecurityEventPayload(event: SecurityEvent) {
  return {
    securityEvent: {
      eventId: event.eventId,
      timestamp: event.timestamp,
      sourceType: event.sourceType,
      subject: event.subject,
      action: event.action,
      object: event.object,
      context: event.context ?? {},
      severity: event.severity,
      riskScore: event.riskScore,
      labels: event.labels ?? [],
    },
  };
}

export async function runDefenseWorkflow(event: SecurityEvent): Promise<WorkflowRunResult> {
  const body = buildWorkflowSecurityEventPayload(event);
  let response: Response;
  try {
    response = await fetch(`${AGENT_BRAIN_URL}/workflow/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    throw new Error(
      `无法连接 agent-brain 服务（${AGENT_BRAIN_URL}），请确认其已在 8001 端口启动后再次尝试。原始错误：${msg}`,
    );
  }
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `调用 /workflow/run 失败：HTTP ${response.status}`);
  }
  return response.json() as Promise<WorkflowRunResult>;
}
