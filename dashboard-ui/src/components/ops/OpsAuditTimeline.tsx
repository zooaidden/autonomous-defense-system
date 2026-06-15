import type { OpsAuditTrailItem } from "../../types/ops";

interface OpsAuditTimelineProps {
  trail: OpsAuditTrailItem[];
}

const STEP_LABEL: Record<string, string> = {
  received_instruction: "接收用户指令",
  prompt_injection_detected: "反提示注入护栏",
  config_guard_blocked: "配置确定性护栏",
  parsed_intent: "意图识别完成",
  dangerous_intent_detected: "高危意图识别",
  mcp_context_collected: "MCP 状态采集",
  safety_validated: "安全闸门校验",
  safety_validation_blocked: "安全闸门拦截",
  executed_or_blocked: "执行 / 阻断决策",
  execution_skipped: "执行已跳过",
  final_answer_generated: "生成最终回答",
};

function stepLabel(step: string): string {
  return STEP_LABEL[step] ?? step;
}

// Localize the raw status enum returned by the backend so the timeline
// reads as Chinese ops jargon instead of capitalized English keywords.
const STATUS_LABEL: Record<string, string> = {
  OK: "通过",
  EXECUTED: "已执行",
  ALLOW: "放行",
  SUCCESS: "成功",
  WARN: "提醒",
  SKIPPED: "跳过",
  SKIP: "跳过",
  DETECTED: "已识别",
  REQUIRE_APPROVAL: "需审批",
  PENDING_APPROVAL: "待审批",
  BLOCK: "已阻断",
  BLOCKED: "已阻断",
  REJECTED: "已拒绝",
  ERROR: "异常",
  FAILED: "失败",
  UNKNOWN: "未知",
};

function statusZh(status: string): string {
  return STATUS_LABEL[status.toUpperCase()] ?? status;
}

function stepTone(status: string): "ok" | "warn" | "danger" | "muted" | "info" {
  const s = status.toUpperCase();
  if (s === "OK" || s === "EXECUTED" || s === "ALLOW" || s === "SUCCESS") return "ok";
  if (
    s === "REQUIRE_APPROVAL" ||
    s === "PENDING_APPROVAL" ||
    s === "WARN" ||
    s === "SKIPPED" ||
    s === "SKIP" ||
    s === "DETECTED"
  )
    return "warn";
  if (s === "BLOCK" || s === "BLOCKED" || s === "REJECTED" || s === "ERROR" || s === "FAILED") return "danger";
  return "info";
}

function fmtTime(ts: string): string {
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts;
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  } catch {
    return ts;
  }
}

export function OpsAuditTimeline({ trail }: OpsAuditTimelineProps) {
  if (!trail || trail.length === 0) {
    return (
      <section className="panel-glow">
        <header className="ops-section-head">
          <h3>审计链路</h3>
          <span className="muted">暂无事件</span>
        </header>
      </section>
    );
  }

  return (
    <section className="panel-glow">
      <header className="ops-section-head">
        <h3>审计链路 · Audit Trail</h3>
        <span className="muted">共 {trail.length} 个阶段</span>
      </header>
      <ol className="ops-audit-timeline">
        {trail.map((it, idx) => {
          const tone = stepTone(it.status);
          return (
            <li key={`${it.step}-${idx}`} className={`ops-audit-item tone-${tone}`}>
              <span className="ops-audit-marker" aria-hidden>
                <span className="ops-audit-marker-dot" />
              </span>
              <div className="ops-audit-body">
                <div className="ops-audit-row">
                  <span className="ops-audit-step">{idx + 1}. {stepLabel(it.step)}</span>
                  <span
                    className={`ops-audit-status tone-${tone}`}
                    title={it.status}
                  >
                    {statusZh(it.status)}
                  </span>
                  <span className="ops-audit-time">{fmtTime(it.timestamp)}</span>
                </div>
                <p className="ops-audit-msg">{it.message}</p>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
