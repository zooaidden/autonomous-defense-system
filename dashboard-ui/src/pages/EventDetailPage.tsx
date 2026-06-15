// Event detail — shows the SecurityEvent record and lets the user dispatch a
// new defense workflow task. The task runs on the global TaskStore so the
// user can navigate away while it's in flight.

import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { fetchChainView, fetchEventById } from "../api/services";
import { FinalStrategyPanel } from "../components/FinalStrategyPanel";
import { McpTracePanel } from "../components/McpTracePanel";
import { SafetyChecksPanel } from "../components/SafetyChecksPanel";
import { AgentRelayProgress } from "../components/AgentRelayProgress";
import { OpsAuditFileBar } from "../components/ops/OpsAuditFileBar";
import { OpsConfigGuardCard } from "../components/ops/OpsConfigGuardCard";
import { OpsInjectionGuardCard } from "../components/ops/OpsInjectionGuardCard";
import { Button } from "../ui/Button";
import { Chip } from "../ui/Chip";
import { notify } from "../ui/Toast";
import { useEventStore } from "../store/eventStore";
import { useTaskStore } from "../store/taskStore";
import type { ChainView, SecurityEvent } from "../types";
import { describeSecurityEventRow } from "../utils/humanReadable/describeSecurityEvent";

export function EventDetailPage() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const [event, setEvent] = useState<SecurityEvent | null>(null);
  const [chain, setChain] = useState<ChainView | null>(null);
  const startWorkflow = useTaskStore((s) => s.startWorkflow);
  const appendDerivedEvent = useEventStore((s) => s.appendDerivedEvent);
  const disposition = useEventStore((s) => (event ? s.disposition[event.eventId] : undefined));
  const linkedTask = useTaskStore((s) =>
    disposition?.taskId ? s.tasks[disposition.taskId] : undefined,
  );

  useEffect(() => {
    void fetchEventById(id).then(setEvent);
    void fetchChainView(id).then(setChain);
  }, [id]);

  function handleDispatch() {
    if (!event) return;
    const taskId = startWorkflow(event, { kind: "workflow" });
    appendDerivedEvent(event, taskId);
    notify("已派发处置任务，可在任务中心或博弈页观察进度", "info");
    navigate("/tasks");
  }

  // IMPORTANT: keep all hook calls above any early return so that React's
  // hook-order invariant holds across renders.
  const row = useMemo(
    () => (event ? describeSecurityEventRow(event) : null),
    [event],
  );

  if (!event || !row) return <div>加载中…</div>;

  const decision = chain?.coordinatorDecision;
  const mcpTrace = decision?.mcp_trace ?? [];
  const safetyChecks = decision?.safety_checks ?? [];
  const approvalReasons = decision?.approval_reason ?? [];

  return (
    <section>
      <header className="evt-detail-head">
        <div>
          <Link to="/events" className="muted">
            ← 返回事件中心
          </Link>
          <h1>事件详情</h1>
          <p className="muted">查看单条事件的元数据、感知到处置的全链路追踪，并可向 agent-brain 派发新的防御任务。</p>
        </div>
        <div className="evt-detail-head-actions">
          <Button variant="primary" onClick={handleDispatch} leadingIcon="▶">
            派发处置任务
          </Button>
          {linkedTask ? (
            <Button variant="secondary" size="sm" onClick={() => navigate("/tasks")}>
              查看关联任务 →
            </Button>
          ) : null}
        </div>
      </header>

      {linkedTask ? (
        <article className="dash-latest-task">
          <header className="dash-latest-task-head">
            <div>
              <span className="task-tray-item-kind">关联任务</span>
              <h3>{linkedTask.title}</h3>
              <p className="muted">{linkedTask.subtitle ?? "—"}</p>
            </div>
            <Chip
              tone={
                linkedTask.status === "running"
                  ? "info"
                  : linkedTask.status === "success"
                    ? "ok"
                    : linkedTask.status === "error"
                      ? "danger"
                      : "neutral"
              }
              leadingDot
            >
              {linkedTask.status === "running" ? "运行中" : linkedTask.status === "success" ? "已完成" : "出错"}
            </Chip>
          </header>
          <AgentRelayProgress phases={linkedTask.phases} activePhase={linkedTask.activePhase} />
        </article>
      ) : null}

      <div className="panel">
        <div className="evt-detail-meta">
          <div>
            <span className="muted">事件编号</span>
            <strong>{event.eventId}</strong>
          </div>
          <div>
            <span className="muted">时间</span>
            <strong>{row.timestampDisplay}</strong>
          </div>
          <div>
            <span className="muted">来源</span>
            <strong>{row.sourceText}</strong>
          </div>
          <div>
            <span className="muted">主体</span>
            <strong>{event.subject}</strong>
          </div>
          <div>
            <span className="muted">行为</span>
            <strong>{row.actionText}</strong>
          </div>
          <div>
            <span className="muted">客体</span>
            <strong>{event.object}</strong>
          </div>
          <div>
            <span className="muted">严重程度</span>
            <Chip tone={row.severityTone === "danger" ? "danger" : row.severityTone === "warn" ? "warn" : "ok"}>
              {row.severityText}
            </Chip>
          </div>
          <div>
            <span className="muted">风险分</span>
            <strong>{event.riskScore.toFixed(2)}</strong>
          </div>
        </div>
      </div>

      {chain && (
        <div className="panel">
          <h3>链路状态</h3>
          <p>
            博弈编号：<code>{chain.debate.debateId}</code>
          </p>
          <p>下一步：{chain.debate.nextAction}</p>
          <p>决策原因：{chain.debate.decisionReason}</p>
          {linkedTask?.result?.workflow ? (
            <OpsAuditFileBar
              requestId={linkedTask.result.workflow.requestId}
              auditFile={linkedTask.result.workflow.auditFile ?? null}
            />
          ) : null}
        </div>
      )}

      {linkedTask?.result?.workflow ? (
        <div className="ops-guard-grid">
          <OpsInjectionGuardCard
            envelope={linkedTask.result.workflow.promptInjection}
          />
          <OpsConfigGuardCard envelope={linkedTask.result.workflow.configGuard} />
        </div>
      ) : null}

      {decision && (
        <div className="two-col">
          <FinalStrategyPanel decision={decision} />
          <SafetyChecksPanel
            checks={safetyChecks}
            humanApprovalRequired={decision.human_approval_required}
            autoExecutionAllowed={decision.auto_execution_allowed}
            approvalReasons={approvalReasons}
          />
        </div>
      )}

      <McpTracePanel trace={mcpTrace} title="MCP 工具调用链（事件视角）" />
    </section>
  );
}
