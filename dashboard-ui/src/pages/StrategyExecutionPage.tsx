// /executions — strategy execution + rollback timeline. Each row collapses
// into a Disclosure that exposes the human-readable execution descriptor
// produced by humanReadable/describeExecution.

import { useEffect, useMemo, useState } from "react";
import { useLocation, Link } from "react-router-dom";
import { ActuatorWorkflowSummaryPanel } from "../components/ActuatorArtifactsPanel";
import { FinalStrategyPanel } from "../components/FinalStrategyPanel";
import { McpTracePanel } from "../components/McpTracePanel";
import { SafetyChecksPanel } from "../components/SafetyChecksPanel";
import { Button } from "../ui/Button";
import { Chip } from "../ui/Chip";
import { Disclosure } from "../ui/Disclosure";
import { EmptyState } from "../ui/EmptyState";
import { fetchChainView, fetchExecutions } from "../api/services";
import { mockHumanApprovalDecision } from "../mock/data";
import type { ChainView, CoordinatorDecision, ExecutionRecord } from "../types";
import type { ActuatorWorkflowResponse, WorkflowRunResult } from "../types/workflow";
import {
  WORKFLOW_LOCAL_STORAGE_KEY,
  parsePersistedWorkflow,
} from "../utils/workflowDisplay";
import {
  describeExecutionHuman,
  type ExecutionDescriptor,
} from "../utils/humanReadable/describeExecution";

type DemoScenario = "approved" | "requires_approval";

interface LocationWorkflowState {
  workflowResult?: WorkflowRunResult;
}

export function StrategyExecutionPage() {
  const location = useLocation();
  const [executions, setExecutions] = useState<ExecutionRecord[]>([]);
  const [chain, setChain] = useState<ChainView | null>(null);
  const [workflowActuator, setWorkflowActuator] = useState<ActuatorWorkflowResponse | null>(null);
  const [scenario, setScenario] = useState<DemoScenario>("approved");

  useEffect(() => {
    void fetchExecutions().then(setExecutions);
    void fetchChainView("evt-20260414-001").then(setChain);
  }, []);

  useEffect(() => {
    const nav = (location.state as LocationWorkflowState | null)?.workflowResult?.actuatorResponse;
    if (nav && typeof nav === "object") {
      setWorkflowActuator(nav);
      return;
    }
    try {
      const raw = localStorage.getItem(WORKFLOW_LOCAL_STORAGE_KEY);
      const parsed = parsePersistedWorkflow(raw ?? "");
      if (parsed?.actuatorResponse && typeof parsed.actuatorResponse === "object") {
        setWorkflowActuator(parsed.actuatorResponse);
        return;
      }
    } catch {
      /* ignore */
    }
    setWorkflowActuator(null);
  }, [location.state, location.key]);

  const decision: CoordinatorDecision | undefined = useMemo(() => {
    if (scenario === "requires_approval") return mockHumanApprovalDecision;
    return chain?.coordinatorDecision;
  }, [chain, scenario]);

  const mcpTrace = decision?.mcp_trace ?? [];
  const safetyChecks = decision?.safety_checks ?? [];
  const approvalReasons = decision?.approval_reason ?? [];

  return (
    <section>
      <header className="exec-page-head">
        <div>
          <h1>策略执行</h1>
          <p className="muted">
            展示防御策略下发到执行器（actuator-service）后的执行记录、回滚状态、生成工件以及人工审批边界。
          </p>
        </div>
        <div className="exec-page-head-actions">
          <Button
            variant={scenario === "approved" ? "primary" : "secondary"}
            size="sm"
            onClick={() => setScenario("approved")}
          >
            低风险 · 自动执行
          </Button>
          <Button
            variant={scenario === "requires_approval" ? "primary" : "secondary"}
            size="sm"
            onClick={() => setScenario("requires_approval")}
          >
            高风险 · 需人工审批
          </Button>
        </div>
      </header>

      {workflowActuator ? (
        <ActuatorWorkflowSummaryPanel response={workflowActuator} />
      ) : (
        <div className="panel">
          <h3>最近一次执行器回执</h3>
          <p className="muted">
            尚未加载执行器快照。请在
            <Link to="/events"> 事件中心 </Link>选择一条事件后派发处置任务，或在
            <Link to="/"> 防御态势 </Link>页运行 Sandbox 演示。
          </p>
        </div>
      )}

      {chain && scenario === "approved" && (
        <div className="panel two-col">
          <div>
            <h3>防御策略详情</h3>
            <dl className="exec-strategy-dl">
              <div>
                <dt>策略编号</dt>
                <dd>
                  <code>{chain.strategy.strategyId}</code>
                </dd>
              </div>
              <div>
                <dt>威胁类型</dt>
                <dd>{chain.strategy.threatType}</dd>
              </div>
              <div>
                <dt>作用层级</dt>
                <dd>{chain.strategy.targetLayer}</dd>
              </div>
              <div>
                <dt>置信度</dt>
                <dd>{(chain.strategy.confidence * 100).toFixed(0)}%</dd>
              </div>
              <div>
                <dt>策略要点</dt>
                <dd>{chain.strategy.rationale}</dd>
              </div>
            </dl>
          </div>
          <div>
            <h3>形式化校验</h3>
            <dl className="exec-strategy-dl">
              <div>
                <dt>是否通过</dt>
                <dd>
                  <Chip tone={chain.verification.passed ? "ok" : "danger"} leadingDot>
                    {chain.verification.passed ? "通过" : "未通过"}
                  </Chip>
                </dd>
              </div>
              <div>
                <dt>说明</dt>
                <dd>{chain.verification.reason}</dd>
              </div>
              <div>
                <dt>违反约束</dt>
                <dd>{chain.verification.violatedConstraints.length} 条</dd>
              </div>
              <div>
                <dt>提示项</dt>
                <dd>{chain.verification.warnings.length} 条</dd>
              </div>
            </dl>
          </div>
        </div>
      )}

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

      <McpTracePanel trace={mcpTrace} title="MCP 工具调用链（执行视角）" />

      <section className="exec-records">
        <header className="exec-records-head">
          <h3>执行记录</h3>
          <span className="muted">共 {executions.length} 条</span>
        </header>
        {!executions.length ? (
          <EmptyState
            icon="📋"
            title="暂无执行记录"
            description="执行器尚未接收到任何下发指令。运行一次 Sandbox 演示或派发事件处置任务后将出现在此处。"
          />
        ) : (
          <div className="exec-records-list">
            {executions.map((record) => (
              <ExecutionRow key={record.executionId} record={record} />
            ))}
          </div>
        )}
      </section>
    </section>
  );
}

function ExecutionRow({ record }: { record: ExecutionRecord }) {
  const desc: ExecutionDescriptor = useMemo(() => describeExecutionHuman(record), [record]);

  const summary = (
    <div className="exec-row-summary">
      <code className="exec-row-id">{desc.executionId}</code>
      <span className="exec-row-strategy" title={desc.strategyId}>
        {desc.strategyId}
      </span>
      <Chip
        tone={
          desc.statusTone === "ok"
            ? "ok"
            : desc.statusTone === "danger"
              ? "danger"
              : desc.statusTone === "warn"
                ? "warn"
                : "neutral"
        }
        leadingDot
      >
        {desc.statusText}
      </Chip>
      <Chip
        tone={
          desc.rollbackTone === "ok"
            ? "ok"
            : desc.rollbackTone === "warn"
              ? "warn"
              : desc.rollbackTone === "danger"
                ? "danger"
                : "neutral"
        }
      >
        回滚 · {desc.rollbackText}
      </Chip>
      <span className="muted exec-row-time">{desc.startedAt}</span>
    </div>
  );

  return (
    <Disclosure summary={summary} tone={desc.statusTone}>
      <dl className="exec-row-dl">
        <div>
          <dt>开始时间</dt>
          <dd>{desc.startedAt}</dd>
        </div>
        <div>
          <dt>结束时间</dt>
          <dd>{desc.endedAt}</dd>
        </div>
        <div>
          <dt>耗时</dt>
          <dd>{desc.durationText}</dd>
        </div>
        <div>
          <dt>建议生效时长</dt>
          <dd>{desc.ttlText}</dd>
        </div>
        <div>
          <dt>结果消息</dt>
          <dd>{desc.resultMessage}</dd>
        </div>
        {desc.failureReason ? (
          <div>
            <dt>失败原因</dt>
            <dd className="exec-row-fail">{desc.failureReason}</dd>
          </div>
        ) : null}
      </dl>
    </Disclosure>
  );
}
