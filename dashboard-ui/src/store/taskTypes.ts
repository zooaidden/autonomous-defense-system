// Shared task / phase model used by the TaskStore and every UI consumer
// (FAB, /tasks page, dashboard, debate page). Kept in its own file so the
// types can be referenced without pulling in the zustand runtime.

import type { SecurityEvent } from "../types";
import type { WorkflowRunResult } from "../types/workflow";
import type { OpsChatResponse } from "../types/ops";

export type TaskKind = "workflow" | "ops" | "sandbox-demo";

export type TaskStatus = "pending" | "running" | "success" | "error" | "canceled";

export type PhaseStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface TaskPhase {
  key: string;
  label: string;
  icon: string;
  status: PhaseStatus;
  startedAt?: string;
  endedAt?: string;
  detail?: string;
}

// Reduced "agent says" turn shape. Lets us drive the relay progress + chat
// bubble FAB without holding a full WorkflowRunResult during the in-flight
// phase.
export interface DerivedDebateTurn {
  actor: string;
  message: string;
  timestamp: string;
}

export interface Task {
  id: string;
  kind: TaskKind;
  title: string;
  subtitle?: string;
  status: TaskStatus;
  phases: TaskPhase[];
  // Optimistic phase index — drives "current speaker" highlight. The store
  // walks it forward via setInterval until the real result arrives.
  activePhase: number;
  startedAt: string;
  endedAt?: string;
  // Original request payload (event for workflow, instruction string for ops).
  request: {
    kind: TaskKind;
    event?: SecurityEvent;
    instruction?: string;
  };
  // The reduced debate turns that have been "spoken" so far. For ops tasks
  // this stays empty; for workflow tasks the store fills it from the real
  // result when the POST returns.
  derivedTurns: DerivedDebateTurn[];
  result?: {
    workflow?: WorkflowRunResult;
    ops?: OpsChatResponse;
  };
  error?: string;
  // Event row id appended to the EventStore when this task started — lets us
  // colour that row with the task's evolving disposition chip.
  derivedEventId?: string;
}

// Phase templates: phase shape is identical for every workflow/sandbox task and
// for every ops task. Real backend timings later overwrite the optimistic ones.
export const WORKFLOW_PHASES: Array<Omit<TaskPhase, "status">> = [
  { key: "perceive", label: "感知接入", icon: "📡" },
  { key: "planner", label: "Planner 规划", icon: "🧠" },
  { key: "red-team", label: "Red-Teamer 挑战", icon: "🛡" },
  { key: "coordinator", label: "Coordinator 裁决", icon: "🎯" },
  { key: "verify", label: "形式化校验", icon: "✓" },
  { key: "execute", label: "策略下发", icon: "⚙" },
];

export const OPS_PHASES: Array<Omit<TaskPhase, "status">> = [
  { key: "intake", label: "接收指令", icon: "📥" },
  { key: "intent", label: "意图解析", icon: "🧭" },
  { key: "mcp", label: "MCP 采集", icon: "🔌" },
  { key: "safety", label: "安全闸门", icon: "🛡" },
  { key: "execute", label: "最小权限执行", icon: "⚙" },
  { key: "answer", label: "生成回答", icon: "💬" },
];

// Mean wall-clock per phase used for the optimistic relay timer (ms). Values
// are intentionally short for a livelier UX — final phase always ends as soon
// as the real backend POST returns.
export const PHASE_TIMING_MS_WORKFLOW: Record<string, number> = {
  perceive: 600,
  planner: 1800,
  "red-team": 1800,
  coordinator: 1800,
  verify: 1400,
  execute: 1600,
};

export const PHASE_TIMING_MS_OPS: Record<string, number> = {
  intake: 400,
  intent: 700,
  mcp: 1400,
  safety: 700,
  execute: 1200,
  answer: 800,
};
