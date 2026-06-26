// Dashboard page — high level KPIs, a Sandbox demo launcher, and a live
// preview of the most recent task's progress. The Sandbox demo dispatches to
// the global TaskStore so the user can keep browsing while it runs.

import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { useShallow } from "zustand/react/shallow";
import { EventTrendChart } from "../components/EventTrendChart";
import { EventIngestNotice } from "../components/EventIngestNotice";
import { MetricCard } from "../components/MetricCard";
import { AgentRelayProgress } from "../components/AgentRelayProgress";
import { Button } from "../ui/Button";
import { Chip } from "../ui/Chip";
import { fetchEvents, fetchExecutions } from "../api/services";
import { useEventStore, selectAllEvents } from "../store/eventStore";
import {
  selectLatestTask,
  selectRunningTasks,
  useTaskStore,
} from "../store/taskStore";
import { buildSandboxAutoDefenseDemoEvent } from "../demo/sandboxAutoDefenseDemo";
import { notify } from "../ui/Toast";
import type { ExecutionRecord } from "../types";

export function DashboardPage() {
  const navigate = useNavigate();
  const setInitialEvents = useEventStore((s) => s.setInitialEvents);
  const appendDerivedEvent = useEventStore((s) => s.appendDerivedEvent);
  // Array-returning selectors must use `useShallow` under Zustand v5 to keep
  // referential identity stable across renders and avoid an infinite loop.
  const events = useEventStore(useShallow(selectAllEvents));
  const startWorkflow = useTaskStore((s) => s.startWorkflow);
  const latestTask = useTaskStore(selectLatestTask);
  const runningTasks = useTaskStore(useShallow(selectRunningTasks));

  // Local-only executions list (no global store yet — used purely for KPI calc).
  const [executions, setExecutions] = useStateExecutions();

  useEffect(() => {
    void fetchEvents().then(setInitialEvents);
    void fetchExecutions().then(setExecutions);
  }, [setInitialEvents, setExecutions]);

  const today = useMemo(() => {
    const nowDate = new Date().toISOString().slice(0, 10);
    const todayEvents = events.filter((e) => e.timestamp.startsWith(nowDate));
    const highRisk = todayEvents.filter((e) => e.riskScore >= 0.8).length;
    const rollbackCount = executions.filter((x) => x.rollbackStatus === "SUCCEEDED").length;
    return {
      todayCount: todayEvents.length,
      highRisk,
      executed: executions.length,
      rollbackCount,
    };
  }, [events, executions]);

  function handleSandboxDemo() {
    const demoEvent = buildSandboxAutoDefenseDemoEvent();
    const taskId = startWorkflow(demoEvent, { kind: "sandbox-demo" });
    appendDerivedEvent(demoEvent, taskId);
    notify("已派发 Sandbox 演示任务，可随意切换页面观察进度", "info", 4200);
  }

  const isDemoRunning = runningTasks.some(
    (t) => t.kind === "sandbox-demo" && t.status === "running",
  );

  return (
    <section>
      <header className="dash-hero">
        <div>
          <h1>防御态势</h1>
          <p className="muted">
            一站式展示安全事件流入量、智能体协同链路与策略执行成效；点击下方 Sandbox 演示后可在任意页面继续观察任务进度。
          </p>
        </div>
        <div className="dash-hero-actions">
          <Button
            variant="primary"
            onClick={handleSandboxDemo}
            loading={isDemoRunning}
            leadingIcon="▶"
          >
            {isDemoRunning ? "演示运行中" : "运行 Sandbox 自动防御演示"}
          </Button>
          <Button
            variant="secondary"
            onClick={() => navigate("/tasks")}
            size="sm"
            leadingIcon="⚡"
          >
            打开任务中心
          </Button>
        </div>
      </header>

      <EventIngestNotice />

      {latestTask ? (
        <motion.article
          className="dash-latest-task"
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.24, ease: "easeOut" }}
        >
          <header className="dash-latest-task-head">
            <div>
              <span className="task-tray-item-kind">最近任务</span>
              <h3>{latestTask.title}</h3>
              {latestTask.subtitle ? (
                <p className="muted">{latestTask.subtitle}</p>
              ) : null}
            </div>
            <Chip
              tone={
                latestTask.status === "running"
                  ? "info"
                  : latestTask.status === "success"
                    ? "ok"
                    : latestTask.status === "error"
                      ? "danger"
                      : "neutral"
              }
              leadingDot
            >
              {latestTask.status === "running"
                ? "运行中"
                : latestTask.status === "success"
                  ? "已完成"
                  : latestTask.status === "error"
                    ? "出错"
                    : "已取消"}
            </Chip>
          </header>
          <AgentRelayProgress
            phases={latestTask.phases}
            activePhase={latestTask.activePhase}
          />
        </motion.article>
      ) : null}

      <div className="metrics-grid">
        <MetricCard
          title="今日事件数"
          value={today.todayCount}
          subtitle="感知层上报事件"
          onClick={() => navigate("/events")}
        />
        <MetricCard
          title="高风险事件数"
          value={today.highRisk}
          subtitle="riskScore ≥ 0.8"
          tone="danger"
          onClick={() => navigate("/events")}
        />
        <MetricCard
          title="已执行策略数"
          value={today.executed}
          subtitle="执行层成功记录"
          onClick={() => navigate("/executions")}
        />
        <MetricCard
          title="回滚次数"
          value={today.rollbackCount}
          subtitle="自动/手动回滚合计"
          tone="warn"
          onClick={() => navigate("/executions")}
        />
      </div>

      <div style={{ marginTop: 16 }}>
        <EventTrendChart events={events} windowDays={7} />
      </div>
    </section>
  );
}

// Tiny local hook to keep the page readable — wraps useState for executions.
function useStateExecutions(): [ExecutionRecord[], (records: ExecutionRecord[]) => void] {
  const [v, setV] = useState<ExecutionRecord[]>([]);
  return [v, setV];
}
