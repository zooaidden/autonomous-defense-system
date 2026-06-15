// /debate — multi-agent collaboration replay. Subscribes to the TaskStore so
// the conversation can be visualized live even when the user starts the
// workflow from another page. Raw JSON is no longer surfaced inline; a
// developer-tools sheet exposes the audit snapshot on demand.

import { useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { fetchChainView } from "../api/services";
import { USE_MOCK_DATA } from "../api/config";
import { DebateChatBoard } from "../components/debate/DebateChatBoard";
import { DebateProgressRing } from "../components/debate/DebateProgressRing";
import { TopologyStoryboard } from "../components/debate/TopologyStoryboard";
import { ActuatorOutcomePanel } from "../components/ActuatorOutcomePanel";
import { AgentRelayProgress } from "../components/AgentRelayProgress";
import { Button } from "../ui/Button";
import { Sheet } from "../ui/Sheet";
import { Chip } from "../ui/Chip";
import {
  selectLatestTask,
  useTaskStore,
} from "../store/taskStore";
import type { WorkflowRunResult } from "../types/workflow";
import type { CoordinatorDecision } from "../types";
import type { TopologyModel } from "../utils/topologyGraph";
import "../styles/debate-board.css";
import {
  computeWorkflowProgress,
  describeActuatorHuman,
  describeChallengeHuman,
  describeCoordinatorDecisionHuman,
  describeFinalStrategyHuman,
  describeMcpCallHuman,
  describeVerificationHuman,
} from "../utils/humanReadable";
import { buildTopologyModel, highlightChainDepth } from "../utils/topologyGraph";
import {
  WORKFLOW_LOCAL_STORAGE_KEY,
  bundleFromChainView,
  bundleFromWorkflow,
  parsePersistedWorkflow,
  pickMcpTrace,
  type UnifiedWorkflowBundle,
} from "../utils/workflowDisplay";

interface LocationWorkflowState {
  workflowResult?: WorkflowRunResult;
}

const EMPTY_TOPOLOGY: TopologyModel = { nodes: [], edges: [], primaryChain: [] };

export function DebateProcessPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const latestTask = useTaskStore(selectLatestTask);
  const [bundle, setBundle] = useState<UnifiedWorkflowBundle | null>(null);
  const [workflowRaw, setWorkflowRaw] = useState<WorkflowRunResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [replayTick, setReplayTick] = useState(0);
  const [replayIdx, setReplayIdx] = useState(-1);
  const [devSheetOpen, setDevSheetOpen] = useState(false);

  useEffect(() => {
    setError(null);
    const nav = (location.state as LocationWorkflowState | null)?.workflowResult;

    if (nav) {
      setWorkflowRaw(nav);
      setBundle(bundleFromWorkflow(nav));
      try {
        localStorage.setItem(WORKFLOW_LOCAL_STORAGE_KEY, JSON.stringify(nav));
      } catch {
        /* ignore quota */
      }
      setLoading(false);
      return;
    }

    // Prefer the latest workflow-style task in the global store. Falls back to
    // localStorage and finally to mock when nothing is available yet.
    if (
      latestTask &&
      (latestTask.kind === "workflow" || latestTask.kind === "sandbox-demo") &&
      latestTask.result?.workflow
    ) {
      const wf = latestTask.result.workflow;
      setWorkflowRaw(wf);
      setBundle(bundleFromWorkflow(wf));
      setLoading(false);
      return;
    }

    try {
      const stored = localStorage.getItem(WORKFLOW_LOCAL_STORAGE_KEY);
      if (stored) {
        const parsed = parsePersistedWorkflow(stored);
        if (parsed) {
          setWorkflowRaw(parsed);
          setBundle(bundleFromWorkflow(parsed));
          setLoading(false);
          return;
        }
      }
    } catch {
      /* ignore */
    }

    if (USE_MOCK_DATA) {
      void fetchChainView("evt-20260414-001")
        .then((chain) => {
          setWorkflowRaw(null);
          setBundle(bundleFromChainView(chain));
        })
        .catch((e: unknown) => {
          setError(e instanceof Error ? e.message : String(e));
        })
        .finally(() => setLoading(false));
      return;
    }

    setWorkflowRaw(null);
    setBundle(null);
    setLoading(false);
  }, [location.state, location.key, latestTask?.id, latestTask?.status]);

  const mcpTrace = useMemo(() => (bundle ? pickMcpTrace(bundle) : []), [bundle]);

  const progressPct = useMemo(() => (bundle ? computeWorkflowProgress(bundle) : 0), [bundle]);

  const topoModel = useMemo(() => {
    if (!bundle) return EMPTY_TOPOLOGY;
    return buildTopologyModel(bundle, workflowRaw);
  }, [bundle, workflowRaw]);

  useEffect(() => {
    if (!bundle?.historyTurns?.length) {
      setReplayIdx(-1);
      return undefined;
    }
    setReplayIdx(0);
    let step = 0;
    const timer = window.setInterval(() => {
      step += 1;
      if (step >= bundle.historyTurns.length) {
        window.clearInterval(timer);
        setReplayIdx(bundle.historyTurns.length - 1);
        return;
      }
      setReplayIdx(step);
    }, 900);
    return () => window.clearInterval(timer);
  }, [bundle?.historyTurns?.length, workflowRaw?.eventId, replayTick]);

  const topoDepth = useMemo(() => {
    const chainLen = topoModel.primaryChain.length || topoModel.nodes.length;
    if (replayIdx < 0 || chainLen <= 0) return 0;
    return highlightChainDepth(replayIdx, chainLen);
  }, [topoModel, replayIdx]);

  const strategyLines = useMemo(() => {
    if (!bundle?.finalStrategy) return [];
    return describeFinalStrategyHuman(bundle.finalStrategy as Record<string, unknown>);
  }, [bundle]);

  const coordinatorLines = useMemo(() => {
    const cd = bundle?.coordinatorDecision as CoordinatorDecision | null | undefined;
    if (!cd) return [];
    return describeCoordinatorDecisionHuman(cd);
  }, [bundle]);

  const verificationLines = useMemo(() => {
    const v = bundle?.verification as Record<string, unknown> | null | undefined;
    return describeVerificationHuman(v ?? null);
  }, [bundle]);

  const actuatorIntroLines = useMemo(
    () => describeActuatorHuman(bundle?.actuatorResponse ?? null),
    [bundle],
  );

  const isLiveTaskRunning =
    latestTask?.status === "running" &&
    (latestTask.kind === "workflow" || latestTask.kind === "sandbox-demo");

  function downloadAuditFile() {
    if (!workflowRaw) return;
    const payload = JSON.stringify(workflowRaw, null, 2);
    const blob = new Blob([payload], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `workflow-${workflowRaw.eventId ?? "snapshot"}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  if (loading) {
    return (
      <section>
        <h1 className="debate-page-title">智能体协作</h1>
        <div className="debate-skeleton-layout">
          <div className="debate-skel-col" style={{ height: 160 }} />
          <div className="debate-skel-col debate-skel-chat" />
          <div className="debate-skel-col" style={{ height: 220 }} />
        </div>
        <p className="muted" style={{ marginTop: 12 }}>
          正在加载防御编排结果…
        </p>
      </section>
    );
  }

  if (error) {
    return (
      <section>
        <h1 className="debate-page-title">智能体协作</h1>
        <p className="muted">加载失败：{error}</p>
      </section>
    );
  }

  // Live task in progress — show the agent relay even if we don't yet have a
  // finished workflow bundle to render bubbles from.
  if (!bundle && isLiveTaskRunning && latestTask) {
    return (
      <section>
        <header className="debate-page-head">
          <div>
            <h1>智能体协作</h1>
            <p className="muted">当前任务正在运行；完成后将在本页展示完整对话与拓扑。</p>
          </div>
        </header>
        <article className="dash-latest-task">
          <header className="dash-latest-task-head">
            <div>
              <span className="task-tray-item-kind">实时任务</span>
              <h3>{latestTask.title}</h3>
            </div>
            <Chip tone="info" leadingDot>
              运行中
            </Chip>
          </header>
          <AgentRelayProgress phases={latestTask.phases} activePhase={latestTask.activePhase} />
        </article>
      </section>
    );
  }

  if (!bundle) {
    return (
      <section>
        <h1 className="debate-page-title">智能体协作</h1>
        <div className="panel">
          <p>
            暂无任务回放。请在<strong>防御态势</strong>页运行 Sandbox 演示，或在
            <strong>事件中心</strong>选择一条事件后派发处置任务；亦可设置{" "}
            <code>VITE_USE_MOCK=true</code> 加载本地示例。
          </p>
          <Button variant="primary" onClick={() => navigate("/")} leadingIcon="▶">
            返回防御态势
          </Button>
        </div>
      </section>
    );
  }

  const unresolvedLines =
    bundle.unresolved?.length > 0 ? bundle.unresolved.map((c) => describeChallengeHuman(c)) : [];

  return (
    <section className="debate-layout-wrap">
      <header className="debate-page-head">
        <div>
          <h1>智能体协作</h1>
          <p className="muted">
            Planner / Red-Teamer / Coordinator 三方博弈过程的可视化回放，含 MCP 工具调用、形式化校验与执行器反馈。
          </p>
        </div>
        <div className="debate-page-head-actions">
          {workflowRaw ? (
            <Button variant="secondary" size="sm" onClick={() => setDevSheetOpen(true)}>
              开发者工具
            </Button>
          ) : null}
        </div>
      </header>

      {bundle.mode === "workflow" && workflowRaw && (
        <p className="muted workflow-source-hint">
          数据来源：agent-brain POST /workflow/run · eventId={workflowRaw.eventId} · processedAt={workflowRaw.processedAt}
        </p>
      )}
      {bundle.mode === "mock" && USE_MOCK_DATA && (
        <p className="muted workflow-source-hint">数据来源：本地示例（VITE_USE_MOCK=true）</p>
      )}

      <div className="debate-board-layout">
        <aside className="debate-board-aside">
          <DebateProgressRing progress={progressPct} />
        </aside>

        <main className="debate-board-main">
          <div className="debate-board-toolbar">
            <span className="muted">博弈回放 · 右侧拓扑随回合递进</span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setReplayTick((x) => x + 1)}
            >
              重新回放
            </Button>
          </div>
          <div className="debate-chat-scroll">
            <DebateChatBoard
              turns={bundle.historyTurns}
              activeStep={replayIdx >= 0 ? replayIdx : undefined}
            />
          </div>

          <div className="debate-narrative-stack">
            {coordinatorLines.length > 0 && (
              <div className="debate-narrative-card panel">
                <h4>协调决策（可读摘要）</h4>
                <ul>
                  {coordinatorLines.map((line, i) => (
                    <li key={`cord-${i}`}>{line}</li>
                  ))}
                </ul>
              </div>
            )}

            {strategyLines.length > 0 && (
              <div className="debate-narrative-card panel">
                <h4>最终策略说明</h4>
                <ul>
                  {strategyLines.map((line, i) => (
                    <li key={`st-${i}`}>{line}</li>
                  ))}
                </ul>
              </div>
            )}

            {unresolvedLines.length > 0 && (
              <div className="debate-narrative-card panel">
                <h4>未解决挑战</h4>
                <ul>
                  {unresolvedLines.map((line, i) => (
                    <li key={`un-${i}`}>{line}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="debate-narrative-card panel">
              <h4>形式化校验</h4>
              <ul>
                {verificationLines.map((line, i) => (
                  <li key={`vf-${i}`}>{line}</li>
                ))}
              </ul>
            </div>

            {mcpTrace.length > 0 && (
              <div className="debate-narrative-card panel">
                <h4>MCP 工具轨迹（可读摘要）</h4>
                <ul>
                  {mcpTrace.map((call, i) => (
                    <li key={`${call.server}-${call.tool}-${i}`}>{describeMcpCallHuman(call)}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="debate-narrative-card panel">
              <h4>执行器结果（可读摘要）</h4>
              <ul>
                {actuatorIntroLines.map((line, i) => (
                  <li key={`act-${i}`}>{line}</li>
                ))}
              </ul>
            </div>

            <ActuatorOutcomePanel response={bundle.actuatorResponse ?? null} />
          </div>
        </main>

        <aside className="debate-board-aside">
          <TopologyStoryboard model={topoModel} activeDepth={topoDepth} />
        </aside>
      </div>

      <Sheet
        open={devSheetOpen}
        onClose={() => setDevSheetOpen(false)}
        title="开发者工具 · 原始审计数据"
        width={520}
      >
        <p className="muted">
          后端已通过 <code>agent-brain</code> 的 <code>AuditLogger</code> 落盘
          <code> audit-&#123;requestId&#125;.json </code>；此处提供前端持有的同份{" "}
          <code>WorkflowRunResult</code> 快照下载，便于本地排查或归档。
        </p>
        <div className="dev-tools-actions">
          <Button variant="primary" onClick={downloadAuditFile} leadingIcon="⬇" disabled={!workflowRaw}>
            下载当前任务 JSON 快照
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate("/tasks")}
          >
            前往任务中心 →
          </Button>
        </div>
        {workflowRaw ? (
          <details className="dev-tools-details">
            <summary>预览 JSON</summary>
            <pre className="dev-tools-pre">
              <code>{JSON.stringify(workflowRaw, null, 2)}</code>
            </pre>
          </details>
        ) : null}
      </Sheet>
    </section>
  );
}
