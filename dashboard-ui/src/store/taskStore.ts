// Global task store: every long-running backend call (POST /workflow/run,
// POST /ops/chat, and the dashboard Sandbox demo) is started here so it
// survives navigation. Subscribers get live phase updates regardless of which
// route is mounted.
//
// Design notes:
//   - Implemented with Zustand + sessionStorage persist (3 KB runtime, no
//     Provider). The store IS the orchestrator; pages only render and
//     dispatch.
//   - Fetch is fired immediately and tracked by a timer-driven phase walker.
//     When the real result returns we snap the active phase to the last node
//     and freeze the timeline.
//   - On rehydrate (refresh) any task left in `running` is force-marked
//     `error` so the UI never shows an undead progress bar.

import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { SecurityEvent } from "../types";
import { runDefenseWorkflow } from "../api/workflow";
import { postOpsChat } from "../api/ops";
import { pickMockResult } from "../mock/opsMockData";
import { USE_MOCK_DATA } from "../api/config";
import type { WorkflowRunResult } from "../types/workflow";
import type { OpsChatResponse } from "../types/ops";
import {
  OPS_PHASES,
  PHASE_TIMING_MS_OPS,
  PHASE_TIMING_MS_WORKFLOW,
  WORKFLOW_PHASES,
  type DerivedDebateTurn,
  type Task,
  type TaskKind,
  type TaskPhase,
} from "./taskTypes";

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function uid(prefix: string): string {
  // Math.random based: not cryptographically safe but plenty unique for UI
  // task ids; we already log them server-side via the audit logger.
  const seg = () => Math.random().toString(36).slice(2, 8);
  return `${prefix}-${Date.now().toString(36)}-${seg()}`;
}

function nowIso(): string {
  return new Date().toISOString();
}

function clonePhases(template: Array<Omit<TaskPhase, "status">>): TaskPhase[] {
  return template.map((t) => ({ ...t, status: "pending" }));
}

// Phase walker keys are kept outside the store state to avoid serialization
// (timer ids can't be persisted). Re-created lazily when the store dispatches.
const phaseTimers = new Map<string, ReturnType<typeof setTimeout>>();

function clearPhaseTimer(taskId: string) {
  const t = phaseTimers.get(taskId);
  if (t != null) {
    clearTimeout(t);
    phaseTimers.delete(taskId);
  }
}

// ---------------------------------------------------------------------------
// Store shape
// ---------------------------------------------------------------------------

interface TaskStoreState {
  tasks: Record<string, Task>;
  order: string[];
  // Actions
  startWorkflow: (event: SecurityEvent, opts?: { kind?: "workflow" | "sandbox-demo"; title?: string }) => string;
  startOps: (instruction: string) => string;
  cancel: (id: string) => void;
  removeTask: (id: string) => void;
  clearFinished: () => void;
  // Internal — exposed for tests; not meant for component use.
  _advancePhase: (id: string) => void;
  _completeWorkflow: (id: string, result: WorkflowRunResult) => void;
  _completeOps: (id: string, result: OpsChatResponse) => void;
  _failTask: (id: string, error: string) => void;
}

// Phase walker — schedule next phase progression after `ms`.
function scheduleAdvance(id: string, ms: number) {
  clearPhaseTimer(id);
  const timer = setTimeout(() => {
    useTaskStore.getState()._advancePhase(id);
  }, ms);
  phaseTimers.set(id, timer);
}

// Build derived debate turns from a workflow response (history is already in
// chronological order). Returns at most the first N rows to keep snapshot small.
function workflowToDerivedTurns(result: WorkflowRunResult): DerivedDebateTurn[] {
  const hist = result.debateState?.history ?? [];
  return hist.slice(0, 16).map((h) => ({
    actor: String(h.actor ?? "Agent"),
    message: String(h.message ?? ""),
    timestamp: h.timestamp ? String(h.timestamp) : "",
  }));
}

// Best-effort title generator — keeps the FAB/Task page readable.
function workflowTitle(event: SecurityEvent, isSandbox: boolean): string {
  if (isSandbox) return "沙箱演示 · 自动防御";
  return `事件 ${event.eventId} · 防御编排`;
}
function opsTitle(instruction: string): string {
  const t = instruction.replace(/\s+/g, " ").trim();
  return t.length > 28 ? `${t.slice(0, 26)}…` : t;
}

export const useTaskStore = create<TaskStoreState>()(
  persist(
    (set, get) => ({
      tasks: {},
      order: [],

      startWorkflow: (event, opts) => {
        const kind: TaskKind = opts?.kind === "sandbox-demo" ? "sandbox-demo" : "workflow";
        const id = uid(kind === "sandbox-demo" ? "demo" : "wf");
        const task: Task = {
          id,
          kind,
          title: opts?.title ?? workflowTitle(event, kind === "sandbox-demo"),
          subtitle:
            kind === "sandbox-demo"
              ? "演示低风险事件全链路：感知 → 多智能体协同 → 校验 → 执行"
              : "调用 agent-brain POST /workflow/run",
          status: "running",
          phases: clonePhases(WORKFLOW_PHASES),
          activePhase: 0,
          startedAt: nowIso(),
          request: { kind, event },
          derivedTurns: [],
        };
        // Mark the first phase as running so the UI shows immediate motion.
        task.phases[0] = { ...task.phases[0], status: "running", startedAt: task.startedAt };
        set((s) => ({
          tasks: { ...s.tasks, [id]: task },
          order: [id, ...s.order],
        }));
        scheduleAdvance(id, PHASE_TIMING_MS_WORKFLOW[task.phases[0].key] ?? 1200);

        // Detached fetch — survives unmount.
        void (async () => {
          try {
            const result = await runDefenseWorkflow(event);
            get()._completeWorkflow(id, result);
          } catch (err) {
            get()._failTask(id, err instanceof Error ? err.message : String(err));
          }
        })();
        return id;
      },

      startOps: (instruction) => {
        const id = uid("ops");
        const task: Task = {
          id,
          kind: "ops",
          title: `运维指令 · ${opsTitle(instruction)}`,
          subtitle: "调用 agent-brain POST /ops/chat",
          status: "running",
          phases: clonePhases(OPS_PHASES),
          activePhase: 0,
          startedAt: nowIso(),
          request: { kind: "ops", instruction },
          derivedTurns: [],
        };
        task.phases[0] = { ...task.phases[0], status: "running", startedAt: task.startedAt };
        set((s) => ({
          tasks: { ...s.tasks, [id]: task },
          order: [id, ...s.order],
        }));
        scheduleAdvance(id, PHASE_TIMING_MS_OPS[task.phases[0].key] ?? 800);

        void (async () => {
          try {
            const result = await postOpsChat({ instruction });
            get()._completeOps(id, result);
          } catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            if (USE_MOCK_DATA) {
              // Backend unreachable but mock fallback is enabled — keep flow.
              const mock = pickMockResult(instruction);
              get()._completeOps(id, mock);
              // Annotate with the original error so the FAB can surface a hint.
              set((s) => {
                const cur = s.tasks[id];
                if (!cur) return s;
                return {
                  tasks: { ...s.tasks, [id]: { ...cur, subtitle: `${cur.subtitle ?? ""} · 已回退到本地 mock (${message})` } },
                };
              });
            } else {
              get()._failTask(id, message);
            }
          }
        })();
        return id;
      },

      cancel: (id) => {
        clearPhaseTimer(id);
        set((s) => {
          const cur = s.tasks[id];
          if (!cur) return s;
          if (cur.status !== "running") return s;
          return {
            tasks: {
              ...s.tasks,
              [id]: {
                ...cur,
                status: "canceled",
                endedAt: nowIso(),
                phases: cur.phases.map((p, i) =>
                  i === cur.activePhase ? { ...p, status: "skipped", endedAt: nowIso() } : p,
                ),
              },
            },
          };
        });
      },

      removeTask: (id) => {
        clearPhaseTimer(id);
        set((s) => {
          if (!s.tasks[id]) return s;
          const next = { ...s.tasks };
          delete next[id];
          return { tasks: next, order: s.order.filter((x) => x !== id) };
        });
      },

      clearFinished: () => {
        set((s) => {
          const next: Record<string, Task> = {};
          const order: string[] = [];
          for (const id of s.order) {
            const t = s.tasks[id];
            if (!t) continue;
            if (t.status === "running" || t.status === "pending") {
              next[id] = t;
              order.push(id);
            }
          }
          return { tasks: next, order };
        });
      },

      _advancePhase: (id) => {
        const cur = get().tasks[id];
        if (!cur || cur.status !== "running") return;
        const nextIdx = cur.activePhase + 1;
        // Hold on the second-to-last phase — let the real backend POST drive
        // the final transition. This keeps the timeline honest if the network
        // call is slow.
        const lastWalkable = cur.phases.length - 2;
        if (nextIdx > lastWalkable) {
          // Mark current phase as "still running" indefinitely; the completion
          // callback below replaces it.
          return;
        }
        set((s) => {
          const live = s.tasks[id];
          if (!live) return s;
          const phases = live.phases.map((p, i) => {
            if (i === live.activePhase) return { ...p, status: "done" as const, endedAt: nowIso() };
            if (i === nextIdx) return { ...p, status: "running" as const, startedAt: nowIso() };
            return p;
          });
          return {
            tasks: { ...s.tasks, [id]: { ...live, phases, activePhase: nextIdx } },
          };
        });
        const phaseKey = cur.phases[nextIdx]?.key;
        const timings = cur.kind === "ops" ? PHASE_TIMING_MS_OPS : PHASE_TIMING_MS_WORKFLOW;
        const delay = phaseKey ? timings[phaseKey] ?? 1200 : 1200;
        scheduleAdvance(id, delay);
      },

      _completeWorkflow: (id, result) => {
        clearPhaseTimer(id);
        set((s) => {
          const cur = s.tasks[id];
          if (!cur) return s;
          const lastIdx = cur.phases.length - 1;
          // Mark every phase as done.
          const phases = cur.phases.map((p) => {
            if (p.status === "done") return p;
            return { ...p, status: "done" as const, endedAt: nowIso() };
          });
          const actuator = result.actuatorResponse?.status?.toUpperCase();
          const tone: Task["status"] = actuator === "FAILED" ? "error" : "success";
          return {
            tasks: {
              ...s.tasks,
              [id]: {
                ...cur,
                status: tone,
                activePhase: lastIdx,
                phases,
                endedAt: nowIso(),
                derivedTurns: workflowToDerivedTurns(result),
                result: { ...cur.result, workflow: result },
              },
            },
          };
        });
      },

      _completeOps: (id, result) => {
        clearPhaseTimer(id);
        set((s) => {
          const cur = s.tasks[id];
          if (!cur) return s;
          const lastIdx = cur.phases.length - 1;
          const phases = cur.phases.map((p, i) => {
            if (p.status === "done") return p;
            const finalStatus: TaskPhase["status"] =
              i === lastIdx ? "done" : p.status === "running" ? "done" : "done";
            return { ...p, status: finalStatus, endedAt: nowIso() };
          });
          const decision = result.safetyValidation?.decision;
          const status: Task["status"] =
            decision === "BLOCK" ? "success" /* still "completed" from the user pov */ : "success";
          return {
            tasks: {
              ...s.tasks,
              [id]: {
                ...cur,
                status,
                activePhase: lastIdx,
                phases,
                endedAt: nowIso(),
                result: { ...cur.result, ops: result },
              },
            },
          };
        });
      },

      _failTask: (id, errorMsg) => {
        clearPhaseTimer(id);
        set((s) => {
          const cur = s.tasks[id];
          if (!cur) return s;
          const phases = cur.phases.map((p, i) => {
            if (i === cur.activePhase && p.status === "running") {
              return { ...p, status: "failed" as const, endedAt: nowIso(), detail: errorMsg };
            }
            return p;
          });
          return {
            tasks: {
              ...s.tasks,
              [id]: { ...cur, status: "error", error: errorMsg, endedAt: nowIso(), phases },
            },
          };
        });
      },
    }),
    {
      name: "acd.task-store",
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({ tasks: state.tasks, order: state.order }),
      onRehydrateStorage: () => (rehydrated) => {
        if (!rehydrated) return;
        // Defensive cleanup: any task that was mid-flight when the page was
        // refreshed loses its in-memory fetch promise. Mark it as errored so
        // the UI never shows an undead spinner.
        const stale = Object.values(rehydrated.tasks).filter((t) => t.status === "running");
        if (!stale.length) return;
        stale.forEach((t) => {
          rehydrated.tasks[t.id] = {
            ...t,
            status: "error",
            error: "任务在页面刷新时被中断，请重新发起",
            endedAt: t.endedAt ?? nowIso(),
            phases: t.phases.map((p) =>
              p.status === "running" ? { ...p, status: "failed", endedAt: nowIso() } : p,
            ),
          };
        });
      },
    },
  ),
);

// ---------------------------------------------------------------------------
// Selectors (memoized via shallow comparison in callers; kept simple here)
// ---------------------------------------------------------------------------

export function selectAllTasks(state: TaskStoreState): Task[] {
  return state.order.map((id) => state.tasks[id]).filter(Boolean) as Task[];
}

export function selectRunningTasks(state: TaskStoreState): Task[] {
  return selectAllTasks(state).filter((t) => t.status === "running");
}

export function selectLatestTask(state: TaskStoreState): Task | undefined {
  return state.order.length ? state.tasks[state.order[0]] : undefined;
}

export function selectTaskById(state: TaskStoreState, id: string | undefined): Task | undefined {
  if (!id) return undefined;
  return state.tasks[id];
}
