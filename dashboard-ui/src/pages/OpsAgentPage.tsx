// Top-level page for the OS Security Ops Agent (/ops route).
//
// Dispatching is delegated to the global TaskStore so users can navigate away
// while an ops chat request is in flight; results land on whichever page is
// active when the response arrives.

import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import { AGENT_BRAIN_BASE_URL, USE_MOCK_DATA } from "../api/config";
import { OpsAuditFileBar } from "../components/ops/OpsAuditFileBar";
import { OpsAuditTimeline } from "../components/ops/OpsAuditTimeline";
import { OpsConfigGuardCard } from "../components/ops/OpsConfigGuardCard";
import { OpsEmptyState } from "../components/ops/OpsEmptyState";
import { OpsExecutionCard } from "../components/ops/OpsExecutionCard";
import { OpsInjectionGuardCard } from "../components/ops/OpsInjectionGuardCard";
import { OpsMcpTraceTable } from "../components/ops/OpsMcpTraceTable";
import { OpsProgressStepper } from "../components/ops/OpsProgressStepper";
import { OpsResultHeader } from "../components/ops/OpsResultHeader";
import { OpsRunner } from "../components/ops/OpsRunner";
import { OpsSafetyCard } from "../components/ops/OpsSafetyCard";
import { AgentRelayProgress } from "../components/AgentRelayProgress";
import { Chip } from "../ui/Chip";
import { selectAllTasks, useTaskStore } from "../store/taskStore";
import type { Task } from "../store/taskTypes";
import type { OpsChatResponse } from "../types/ops";
import "../styles/ops.css";

export function OpsAgentPage() {
  const startOps = useTaskStore((s) => s.startOps);
  // Zustand v5: derived arrays need `useShallow` to stay referentially stable.
  const allTasks = useTaskStore(useShallow(selectAllTasks));
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement | null>(null);

  // Find the most recent ops task — used to show the active result when the
  // user lands back on this page after navigating away mid-run.
  const opsTasks = useMemo(
    () => allTasks.filter((t) => t.kind === "ops"),
    [allTasks],
  );
  const activeTask: Task | undefined = useMemo(() => {
    if (activeTaskId) return allTasks.find((t) => t.id === activeTaskId);
    return opsTasks[0];
  }, [allTasks, opsTasks, activeTaskId]);

  const loading = activeTask?.status === "running";
  const result: OpsChatResponse | undefined = activeTask?.result?.ops;

  // Auto-scroll to result when a new run completes.
  useEffect(() => {
    if (!result || loading) return;
    resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result, loading]);

  function runOps(instruction: string) {
    const id = startOps(instruction);
    setActiveTaskId(id);
  }

  const sourceTag = activeTask?.subtitle?.includes("mock") ? "mock" : "live";

  return (
    <section className="ops-page">
      <header className="ops-hero">
        <div className="ops-hero-text">
          <span className="ops-hero-eyebrow">A2 · 麒麟操作系统安全智能运维</span>
          <h1 className="ops-hero-title">智能运维 Agent</h1>
          <p className="ops-hero-sub">
            一个对话式的 OS 运维助手：自然语言进 → MCP 状态采集 → 命令意图安全闸门 → 最小权限只读执行 → 完整审计链路。
            危险动作只会被识别和解释，绝不会真正执行。
          </p>
        </div>
        <div className="ops-hero-meta">
          <div className="ops-hero-meta-item">
            <span className="ops-hero-meta-label">后端服务</span>
            <code className="ops-hero-meta-value">{AGENT_BRAIN_BASE_URL}</code>
          </div>
          <div className="ops-hero-meta-item">
            <span className="ops-hero-meta-label">本地回退</span>
            <code className={`ops-hero-meta-value ${USE_MOCK_DATA ? "is-on" : "is-off"}`}>
              {USE_MOCK_DATA ? "已开启 · 自动回退" : "已关闭 · 仅实时"}
            </code>
          </div>
        </div>
      </header>

      <OpsRunner loading={loading} onRun={runOps} />

      {activeTask && (loading || activeTask.status === "error") ? (
        <article className="dash-latest-task">
          <header className="dash-latest-task-head">
            <div>
              <span className="task-tray-item-kind">当前指令</span>
              <h3>{activeTask.title}</h3>
              <p className="muted">
                {activeTask.subtitle ?? "调用 agent-brain POST /ops/chat"}
              </p>
            </div>
            <Chip
              tone={loading ? "info" : activeTask.status === "error" ? "danger" : "ok"}
              leadingDot
            >
              {loading ? "运行中" : activeTask.status === "error" ? "出错" : "已完成"}
            </Chip>
          </header>
          <AgentRelayProgress phases={activeTask.phases} activePhase={activeTask.activePhase} />
          {activeTask.error ? (
            <div className="task-detail-error">{activeTask.error}</div>
          ) : null}
        </article>
      ) : null}

      <OpsProgressStepper trail={result?.auditTrail} loading={loading} />

      {!result && !loading ? <OpsEmptyState useMock={USE_MOCK_DATA} /> : null}

      {result ? (
        <div className="ops-result-stack" ref={resultRef}>
          <OpsResultHeader result={result} source={sourceTag === "mock" ? "mock" : "live"} />
          <OpsAuditFileBar
            requestId={result.requestId}
            auditFile={result.auditFile ?? null}
          />
          <div className="ops-guard-grid">
            <OpsInjectionGuardCard envelope={result.promptInjection} />
            <OpsConfigGuardCard envelope={result.configGuard} />
            <OpsSafetyCard validation={result.safetyValidation} />
            <OpsExecutionCard execution={result.executionResult ?? null} />
          </div>
          <OpsMcpTraceTable trace={result.mcpTrace ?? []} />
          <OpsAuditTimeline trail={result.auditTrail ?? []} />
        </div>
      ) : null}

      <p className="ops-page-foot muted">
        历史指令可在 <Link to="/tasks">任务中心</Link> 查看；详细审计 JSON 通过 agent-brain 的{" "}
        <code>auditFile</code> 字段落盘，并支持 <Link to="/system">系统状态</Link> 页一键溯源。
      </p>
    </section>
  );
}
