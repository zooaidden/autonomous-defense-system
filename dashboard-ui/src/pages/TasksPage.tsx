// /tasks — the global task center. Lists every task the user has launched
// in this session and lets them inspect each lifecycle.

import { useMemo } from "react";
import { Link } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { useShallow } from "zustand/react/shallow";
import { Chip } from "../ui/Chip";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import { AgentRelayProgress } from "../components/AgentRelayProgress";
import {
  selectAllTasks,
  useTaskStore,
} from "../store/taskStore";
import type { Task } from "../store/taskTypes";

function taskTone(task: Task): "info" | "ok" | "warn" | "danger" | "neutral" {
  if (task.status === "running") return "info";
  if (task.status === "success") return "ok";
  if (task.status === "error") return "danger";
  if (task.status === "canceled") return "neutral";
  return "warn";
}

function taskStatusLabel(task: Task): string {
  if (task.status === "running") return "运行中";
  if (task.status === "success") return "已完成";
  if (task.status === "error") return "出错";
  if (task.status === "canceled") return "已取消";
  return task.status;
}

function kindLabel(task: Task): string {
  if (task.kind === "ops") return "运维 Agent";
  if (task.kind === "sandbox-demo") return "沙箱演示";
  return "防御编排";
}

function fmt(iso: string | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function durationText(task: Task): string {
  if (!task.endedAt) return "—";
  const s = new Date(task.startedAt).getTime();
  const e = new Date(task.endedAt).getTime();
  if (Number.isNaN(s) || Number.isNaN(e) || e <= s) return "—";
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec} 秒`;
  return `${Math.floor(sec / 60)} 分 ${sec % 60} 秒`;
}

export function TasksPage() {
  // Zustand v5 no longer caches selector results internally — `useShallow`
  // gives us referential stability for the derived array so we don't infinite
  // loop on each render.
  const tasks = useTaskStore(useShallow(selectAllTasks));
  const clearFinished = useTaskStore((s) => s.clearFinished);

  const running = useMemo(() => tasks.filter((t) => t.status === "running"), [tasks]);
  const finished = useMemo(() => tasks.filter((t) => t.status !== "running"), [tasks]);

  return (
    <section>
      <header className="tasks-page-head">
        <div className="tasks-page-head-text">
          <h1>任务中心</h1>
          <p>
            所有由本机会话发起的运维 / 防御编排任务，切换页面不会中断；可在此查看每条任务的实时智能体接力与最终结果。
          </p>
        </div>
        <div className="tasks-page-actions">
          {finished.length > 0 ? (
            <Button variant="secondary" size="sm" onClick={() => clearFinished()}>
              清理已完成（{finished.length}）
            </Button>
          ) : null}
        </div>
      </header>

      {!tasks.length ? (
        <EmptyState
          icon="🕸"
          title="暂无任务记录"
          description={
            <>
              在<Link to="/"> 防御态势 </Link>页运行 Sandbox 演示，或在
              <Link to="/ops"> 智能运维 </Link>页输入指令后，任务会自动出现在此处。
            </>
          }
        />
      ) : null}

      {running.length > 0 ? (
        <>
          <h3 className="muted">运行中（{running.length}）</h3>
          <div className="tasks-grid">
            <AnimatePresence initial={false}>
              {running.map((task) => (
                <TaskCard key={task.id} task={task} />
              ))}
            </AnimatePresence>
          </div>
        </>
      ) : null}

      {finished.length > 0 ? (
        <>
          <h3 className="muted" style={{ marginTop: 18 }}>
            历史记录（{finished.length}）
          </h3>
          <div className="tasks-grid">
            <AnimatePresence initial={false}>
              {finished.map((task) => (
                <TaskCard key={task.id} task={task} />
              ))}
            </AnimatePresence>
          </div>
        </>
      ) : null}
    </section>
  );
}

function TaskCard({ task }: { task: Task }) {
  const tone = taskTone(task);
  const removeTask = useTaskStore((s) => s.removeTask);
  const opsLink = task.kind === "ops" && task.result?.ops ? "/ops" : null;
  const debateLink =
    (task.kind === "workflow" || task.kind === "sandbox-demo") && task.result?.workflow
      ? "/debate"
      : null;

  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -6 }}
      transition={{ duration: 0.2 }}
      className="task-detail"
    >
      <header className="task-detail-head">
        <div>
          <span className="task-tray-item-kind">{kindLabel(task)}</span>
          <h3 className="task-detail-title">{task.title}</h3>
          {task.subtitle ? <p className="task-detail-sub">{task.subtitle}</p> : null}
        </div>
        <Chip tone={tone} leadingDot>
          {taskStatusLabel(task)}
        </Chip>
      </header>

      <AgentRelayProgress phases={task.phases} activePhase={task.activePhase} />

      <div className="task-detail-meta">
        <span>开始 {fmt(task.startedAt)}</span>
        <span>耗时 {durationText(task)}</span>
        <span>ID {task.id}</span>
      </div>

      {task.error ? <div className="task-detail-error">{task.error}</div> : null}

      <div className="task-detail-meta" style={{ borderTop: "none", paddingTop: 0 }}>
        {debateLink ? <Link to={debateLink}>查看博弈回放 →</Link> : null}
        {opsLink ? <Link to={opsLink}>查看运维结果 →</Link> : null}
        {task.status !== "running" ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => removeTask(task.id)}
            className="task-detail-clear"
          >
            从记录中移除
          </Button>
        ) : null}
      </div>
    </motion.article>
  );
}
