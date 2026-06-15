import { useMemo } from "react";
import type { OpsExecutionResult } from "../../types/ops";
import { OpsStatusChip } from "./OpsStatusBadge";

interface OpsExecutionCardProps {
  execution?: OpsExecutionResult | null;
}

const STATUS_META: Record<
  string,
  { label: string; tone: "ok" | "warn" | "danger" | "muted" | "info"; icon: string }
> = {
  EXECUTED: { label: "已成功执行", tone: "ok", icon: "✓" },
  SUCCESS: { label: "已成功执行", tone: "ok", icon: "✓" },
  REJECTED: { label: "执行器拒绝", tone: "danger", icon: "✕" },
  PENDING_APPROVAL: { label: "等待审批", tone: "warn", icon: "⌛" },
  BLOCKED: { label: "安全闸门阻断", tone: "danger", icon: "■" },
  INVALID_INPUT: { label: "输入非法", tone: "danger", icon: "✕" },
  TIMEOUT: { label: "执行超时", tone: "warn", icon: "⏱" },
  RUNTIME_ERROR: { label: "运行时错误", tone: "danger", icon: "⚠" },
  SKIPPED: { label: "未执行（跳过）", tone: "muted", icon: "—" },
};

function fmtDuration(ms?: number): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

function fmtTimestamp(ts?: string): string {
  if (!ts) return "—";
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts;
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, "0")}`;
  } catch {
    return ts;
  }
}

function clipText(text: string | undefined, max: number): string {
  if (!text) return "";
  if (text.length <= max) return text;
  return `${text.slice(0, max)}\n… (输出已截断，共 ${text.length} 字符)`;
}

export function OpsExecutionCard({ execution }: OpsExecutionCardProps) {
  const meta = useMemo(() => {
    if (!execution?.status) return STATUS_META.SKIPPED;
    return STATUS_META[execution.status] ?? { label: execution.status, tone: "muted" as const, icon: "·" };
  }, [execution]);

  if (!execution) {
    return (
      <section className="panel-glow ops-exec">
        <header className="ops-section-head">
          <h3>执行结果 · 最小权限执行器</h3>
          <OpsStatusChip label="未执行" tone="muted" icon="—" />
        </header>
        <p className="ops-empty-line">本次请求没有触发命令执行（可能仅做信息查询或被提前阻断）。</p>
      </section>
    );
  }

  return (
    <section className={`panel-glow ops-exec frame-${meta.tone}`}>
      <header className="ops-section-head">
        <h3>执行结果 · 最小权限执行器</h3>
        <OpsStatusChip label={meta.label} tone={meta.tone} icon={meta.icon} />
      </header>

      <dl className="ops-exec-meta">
        {execution.command ? (
          <div>
            <dt>命令</dt>
            <dd>
              <code>{execution.command}</code>
            </dd>
          </div>
        ) : null}
        {execution.executedAs ? (
          <div>
            <dt>执行身份</dt>
            <dd>{execution.executedAs}</dd>
          </div>
        ) : null}
        <div>
          <dt>耗时</dt>
          <dd>{fmtDuration(execution.durationMs)}</dd>
        </div>
        <div>
          <dt>退出码</dt>
          <dd>{execution.exitCode == null ? "—" : execution.exitCode}</dd>
        </div>
        {execution.timeoutSeconds ? (
          <div>
            <dt>超时阈值</dt>
            <dd>{execution.timeoutSeconds}s</dd>
          </div>
        ) : null}
        {execution.startedAt || execution.endedAt ? (
          <div>
            <dt>时间窗</dt>
            <dd>
              {fmtTimestamp(execution.startedAt)} → {fmtTimestamp(execution.endedAt)}
            </dd>
          </div>
        ) : null}
      </dl>

      {execution.reason ? (
        <p className="ops-card-reason">{execution.reason}</p>
      ) : null}

      {execution.stdout ? (
        <details className="ops-exec-output" open>
          <summary>标准输出（截取）</summary>
          <pre className="ops-exec-pre stdout">{clipText(execution.stdout, 1200)}</pre>
        </details>
      ) : null}
      {execution.stderr ? (
        <details className="ops-exec-output">
          <summary>标准错误</summary>
          <pre className="ops-exec-pre stderr">{clipText(execution.stderr, 1200)}</pre>
        </details>
      ) : null}
    </section>
  );
}
