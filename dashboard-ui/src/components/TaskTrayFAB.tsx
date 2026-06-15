// TaskTrayFAB: cross-page sticky floating panel that exposes a live task
// queue. Click the FAB to open a sheet listing every recent task with its
// AgentRelayProgress. The store survives navigation, so the user can move
// freely between pages while still seeing the workflow advance.

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { useShallow } from "zustand/react/shallow";
import { Sheet } from "../ui/Sheet";
import { Chip } from "../ui/Chip";
import { Button } from "../ui/Button";
import { AgentRelayProgress } from "./AgentRelayProgress";
import {
  selectAllTasks,
  selectRunningTasks,
  useTaskStore,
} from "../store/taskStore";
import type { Task } from "../store/taskTypes";
import { statusZh } from "../utils/humanReadable/zh/status";

function tone(task: Task): { label: string; chip: "info" | "ok" | "warn" | "danger" | "neutral" } {
  if (task.status === "running") return { label: "运行中", chip: "info" };
  if (task.status === "success") return { label: "已完成", chip: "ok" };
  if (task.status === "error") return { label: "出错", chip: "danger" };
  if (task.status === "canceled") return { label: "已取消", chip: "neutral" };
  return { label: statusZh(task.status), chip: "warn" };
}

function kindLabel(kind: Task["kind"]): string {
  if (kind === "ops") return "运维 Agent";
  if (kind === "sandbox-demo") return "沙箱演示";
  return "防御编排";
}

function formatStartedAt(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleTimeString();
}

export function TaskTrayFAB() {
  const [open, setOpen] = useState(false);
  // Zustand v5 requires shallow comparison for selectors that derive arrays;
  // returning a fresh array on every render would otherwise infinite-loop.
  const tasks = useTaskStore(useShallow(selectAllTasks));
  const running = useTaskStore(useShallow(selectRunningTasks));

  const runningCount = running.length;
  const finishedCount = useMemo(
    () => tasks.filter((t) => t.status !== "running" && t.status !== "pending").length,
    [tasks],
  );
  const clearFinished = useTaskStore((s) => s.clearFinished);

  if (!tasks.length) return null;

  return (
    <>
      <button
        type="button"
        className={`task-fab ${runningCount ? "is-running" : "is-idle"}`}
        onClick={() => setOpen(true)}
        title={runningCount ? `${runningCount} 个任务运行中` : "查看任务记录"}
      >
        <span className="task-fab-ring" aria-hidden />
        <span className="task-fab-icon" aria-hidden>
          ⚡
        </span>
        <span className="task-fab-text">
          <span className="task-fab-title">{runningCount ? "任务进行中" : "任务记录"}</span>
          <span className="task-fab-sub">
            {runningCount ? `${runningCount} 个运行中` : `${finishedCount} 条历史`}
          </span>
        </span>
      </button>

      <Sheet open={open} onClose={() => setOpen(false)} title="任务中心" width={460}>
        <div className="task-tray">
          <div className="task-tray-actions">
            <Link to="/tasks" className="task-tray-jump" onClick={() => setOpen(false)}>
              查看全部任务详情 →
            </Link>
            {finishedCount > 0 ? (
              <Button variant="ghost" size="sm" onClick={() => clearFinished()}>
                清理已完成
              </Button>
            ) : null}
          </div>

          <AnimatePresence initial={false}>
            {tasks.map((task) => {
              const t = tone(task);
              return (
                <motion.article
                  key={task.id}
                  className={`task-tray-item tone-${t.chip}`}
                  layout
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.2 }}
                >
                  <header className="task-tray-item-head">
                    <span className="task-tray-item-kind">{kindLabel(task.kind)}</span>
                    <Chip tone={t.chip} size="sm" leadingDot>
                      {t.label}
                    </Chip>
                  </header>
                  <h4 className="task-tray-item-title">{task.title}</h4>
                  {task.subtitle ? (
                    <p className="task-tray-item-sub">{task.subtitle}</p>
                  ) : null}
                  <AgentRelayProgress
                    phases={task.phases}
                    activePhase={task.activePhase}
                    size="sm"
                  />
                  <footer className="task-tray-item-foot">
                    <span className="muted">开始于 {formatStartedAt(task.startedAt)}</span>
                    {task.error ? (
                      <span className="task-tray-item-error" title={task.error}>
                        {task.error.length > 56 ? `${task.error.slice(0, 54)}…` : task.error}
                      </span>
                    ) : null}
                  </footer>
                </motion.article>
              );
            })}
          </AnimatePresence>
        </div>
      </Sheet>
    </>
  );
}
