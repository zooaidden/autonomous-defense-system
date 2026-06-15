import { useEffect, useState } from "react";
import type { OpsAuditTrailItem } from "../../types/ops";

// Six-stage stepper that mirrors the backend OpsOrchestrator pipeline.
// The visual is a hexagonal node-chain rather than a single bar so
// users can see exactly which gate is currently active or has tripped.

const STAGE_DEFS: Array<{ key: string; label: string; icon: string; sub: string }> = [
  { key: "received_instruction", label: "接收指令", icon: "✉", sub: "Receive" },
  { key: "parsed_intent", label: "意图识别", icon: "✦", sub: "Parse intent" },
  { key: "mcp_context_collected", label: "MCP 状态", icon: "◎", sub: "MCP context" },
  { key: "safety_validated", label: "安全闸门", icon: "✓", sub: "Safety gate" },
  { key: "executed_or_blocked", label: "最小权限执行", icon: "▶", sub: "Execute" },
  { key: "final_answer_generated", label: "汇总作答", icon: "★", sub: "Final answer" },
];

type NodeState = "pending" | "active" | "done" | "blocked" | "warned";

function classifyStatus(status?: string): NodeState {
  if (!status) return "done";
  const s = status.toUpperCase();
  if (s === "BLOCK" || s === "BLOCKED" || s === "REJECTED") return "blocked";
  if (s === "REQUIRE_APPROVAL" || s === "PENDING_APPROVAL" || s === "WARN" || s === "SKIPPED") return "warned";
  return "done";
}

interface OpsProgressStepperProps {
  // Pass the auditTrail from the response to show concrete state.
  // When omitted, shows a "marching" animation suitable for the loading state.
  trail?: OpsAuditTrailItem[];
  loading?: boolean;
}

export function OpsProgressStepper({ trail, loading = false }: OpsProgressStepperProps) {
  // Walking-cursor animation while loading.
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!loading) return;
    const id = window.setInterval(() => setTick((t) => (t + 1) % STAGE_DEFS.length), 420);
    return () => window.clearInterval(id);
  }, [loading]);

  const trailMap = new Map<string, OpsAuditTrailItem>();
  (trail ?? []).forEach((it) => trailMap.set(it.step, it));

  // Side-event keys that decorate a canonical node with a stronger tone
  // (so the user sees the safety story without growing the stepper to 9 nodes).
  const dangerEvent = trailMap.get("dangerous_intent_detected");
  const blockEvent = trailMap.get("safety_validation_blocked");
  const skipEvent = trailMap.get("execution_skipped");

  const nodes = STAGE_DEFS.map((def, idx) => {
    const event = trailMap.get(def.key);
    let state: NodeState = "pending";
    if (event) state = classifyStatus(event.status);
    if (loading && !event) state = idx === tick ? "active" : "pending";

    // Decorate canonical nodes with side-event tones so the dangerous flow
    // is visible at a glance even though the stepper only renders 6 nodes.
    if (def.key === "parsed_intent" && dangerEvent && state === "done") {
      state = "warned";
    }
    if (def.key === "safety_validated" && blockEvent) {
      state = "blocked";
    }
    if (
      def.key === "executed_or_blocked" &&
      skipEvent &&
      (state === "done" || state === "warned")
    ) {
      state = state === "warned" ? "warned" : "blocked";
    }

    return { def, idx, event, state };
  });

  // Compute a fill ratio so the connecting rail feels "alive".
  const reached = nodes.findIndex((n) => n.state === "pending" || n.state === "active");
  const filledCount = reached === -1 ? nodes.length : Math.max(0, reached);
  const railPct = Math.min(100, (filledCount / (nodes.length - 1)) * 100);

  return (
    <section className="ops-progress panel-glow">
      <header className="ops-progress-head">
        <h3>执行管线进度</h3>
        <span className="muted">Receive → Parse → MCP → Safety → Execute → Answer</span>
      </header>
      <div className="ops-progress-track">
        <div className="ops-progress-rail" />
        <div className="ops-progress-rail-fill" style={{ width: `${railPct}%` }} />
        <ol className="ops-progress-nodes">
          {nodes.map((n) => (
            <li
              key={n.def.key}
              className={`ops-progress-node state-${n.state}`}
              title={n.event ? `${n.event.status} · ${n.event.message}` : n.def.label}
            >
              <span className="ops-progress-node-icon">
                {n.state === "blocked" ? "✕" : n.state === "warned" ? "!" : n.def.icon}
              </span>
              <span className="ops-progress-node-label">{n.def.label}</span>
              <span className="ops-progress-node-sub">{n.def.sub}</span>
              {n.event ? (
                <span className="ops-progress-node-status">{n.event.status}</span>
              ) : (
                <span className="ops-progress-node-status muted">
                  {n.state === "active" ? "running…" : "—"}
                </span>
              )}
            </li>
          ))}
        </ol>
      </div>
    </section>
  );
}
