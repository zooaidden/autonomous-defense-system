// Renders the generatedArtifacts emitted by the actuator-service. Each
// artifact is described via humanReadable.describeArtifactHuman so the UI
// shows structured Chinese rows instead of dumping raw JSON; the original
// payload is still accessible via a "查看原始数据" Disclosure for engineers.

import type { ActuatorWorkflowResponse } from "../types/workflow";
import { Chip } from "../ui/Chip";
import { Disclosure } from "../ui/Disclosure";
import { EmptyState } from "../ui/EmptyState";
import { statusZh } from "../utils/humanReadable/zh/status";
import { describeArtifactHuman } from "../utils/humanReadable/describeArtifact";

interface ArtifactProps {
  artifact: Record<string, unknown>;
}

export function ActuatorArtifactItem({ artifact }: ArtifactProps) {
  const desc = describeArtifactHuman(artifact);
  return (
    <li className="artifact-li">
      <article className={`artifact-card kind-${desc.kind}`}>
        <header className="artifact-card-head">
          <div>
            <h4 className="artifact-card-title">{desc.title}</h4>
            {desc.subtitle ? (
              <p className="artifact-card-sub">{desc.subtitle}</p>
            ) : null}
          </div>
          <div className="artifact-card-badges">
            {desc.badges.map((b, i) => (
              <Chip key={`${b.label}-${i}`} tone={b.tone ?? "neutral"} size="sm">
                {b.label}
              </Chip>
            ))}
          </div>
        </header>

        {desc.yamlBody ? (
          <pre className="artifact-yaml-block">
            <code>{desc.yamlBody}</code>
          </pre>
        ) : null}

        {desc.rows.length > 0 ? (
          <dl className="artifact-rows">
            {desc.rows.map((row) => (
              <div key={row.label}>
                <dt>{row.label}</dt>
                <dd>{row.value}</dd>
              </div>
            ))}
          </dl>
        ) : null}

        <Disclosure
          className="artifact-raw"
          summary={<span className="muted">查看原始数据</span>}
        >
          <pre className="artifact-raw-pre">
            <code>{desc.rawJson}</code>
          </pre>
        </Disclosure>
      </article>
    </li>
  );
}

interface ActuatorArtifactsPanelProps {
  artifacts: Array<Record<string, unknown>>;
}

export function ActuatorArtifactsPanel({ artifacts }: ActuatorArtifactsPanelProps) {
  if (!artifacts.length) {
    return (
      <EmptyState
        icon="∅"
        title="未产生执行工件"
        description="本次执行未生成可下发的策略片段或告警工件。"
      />
    );
  }

  return (
    <ol className="artifacts-list actuator-artifacts-panel">
      {artifacts.map((artifact, idx) => (
        <ActuatorArtifactItem key={`artifact-${idx}`} artifact={artifact} />
      ))}
    </ol>
  );
}

interface ActuatorWorkflowFieldsPanelProps {
  response: ActuatorWorkflowResponse;
}

function formatMaybeTime(iso: unknown): string {
  if (iso == null || iso === "") return "—";
  const s = String(iso);
  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) return d.toLocaleString();
  return s;
}

export function ActuatorWorkflowSummaryPanel({ response }: ActuatorWorkflowFieldsPanelProps) {
  const status = (response.status ?? "").toUpperCase();
  const succeeded = status === "SUCCEEDED";
  const rollbackUp = (response.rollbackStatus ?? "").toUpperCase();
  const rollbackAvail = rollbackUp === "AVAILABLE";

  return (
    <div className="panel actuator-workflow-fields">
      <h3 className="actuator-workflow-main-title">执行器回执</h3>
      <div className="actuator-workflow-banners">
        {succeeded ? (
          <div className="exec-success-banner">
            <Chip tone="ok" leadingDot>
              {statusZh("SUCCEEDED")}
            </Chip>
            <span className="muted">已完成一轮下发仿真</span>
          </div>
        ) : (
          <div className="exec-status-row">
            <span className="muted">状态：</span>
            <Chip
              tone={
                status === "FAILED"
                  ? "danger"
                  : status === "SKIPPED"
                    ? "warn"
                    : status === "PENDING_APPROVAL"
                      ? "warn"
                      : "neutral"
              }
            >
              {statusZh(status) || response.status || "—"}
            </Chip>
          </div>
        )}
        {rollbackAvail ? (
          <div className="rollback-available-banner">
            <Chip tone="warn" leadingDot>
              可回滚
            </Chip>
            <span className="muted">如需撤销可按回滚计划在窗口期内触发</span>
          </div>
        ) : response.rollbackStatus ? (
          <div className="rollback-meta">
            <span className="muted">回滚状态：</span>
            <span>{statusZh(rollbackUp) || response.rollbackStatus}</span>
          </div>
        ) : null}
      </div>

      <dl className="actuator-fields-dl">
        <div>
          <dt>执行编号</dt>
          <dd>{response.executionId ?? "—"}</dd>
        </div>
        <div>
          <dt>策略编号</dt>
          <dd>{response.strategyId ?? "—"}</dd>
        </div>
        <div>
          <dt>结果消息</dt>
          <dd>{response.resultMessage ?? "—"}</dd>
        </div>
        <div>
          <dt>建议生效</dt>
          <dd>{response.ttl != null ? `${Math.round(Number(response.ttl) / 60)} 分钟` : "—"}</dd>
        </div>
        <div>
          <dt>开始时间</dt>
          <dd>{formatMaybeTime(response.startTime)}</dd>
        </div>
        <div>
          <dt>结束时间</dt>
          <dd>{formatMaybeTime(response.endTime)}</dd>
        </div>
      </dl>

      {response.failureReason != null && response.failureReason !== "" ? (
        <div className="actuator-failure-banner">
          <strong>失败原因</strong>
          <p>{String(response.failureReason)}</p>
        </div>
      ) : null}

      {response.message != null && response.message !== "" ? (
        <p className="muted actuator-extra-message">{String(response.message)}</p>
      ) : null}

      <h4 className="artifacts-section-title">生成的工件</h4>
      <ActuatorArtifactsPanel artifacts={response.generatedArtifacts ?? []} />
    </div>
  );
}
