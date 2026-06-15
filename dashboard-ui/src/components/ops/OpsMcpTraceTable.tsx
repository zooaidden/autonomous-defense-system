import type { OpsMcpTraceItem } from "../../types/ops";
import {
  describeMcpArguments,
  toolLabelZh,
} from "../../utils/humanReadable/describeMcp";

interface OpsMcpTraceTableProps {
  trace: OpsMcpTraceItem[];
}

// MCP tool calls rendered as a compact, expandable table. Each row shows
// the Chinese-friendly tool label with the raw id revealed on hover, and
// can be expanded to inspect arguments via `describeMcpArguments`. The
// raw `result` payload is intentionally never displayed - users only see
// the human summary.

// Pull MCP arguments out of an arbitrary trace item. The backend stores
// them under `args` for some clients and `arguments` for others; we try
// both before giving up.
function extractArgs(trace: OpsMcpTraceItem): Record<string, unknown> {
  const candidate = (trace as { args?: unknown; arguments?: unknown }).args
    ?? (trace as { arguments?: unknown }).arguments;
  return candidate && typeof candidate === "object" && !Array.isArray(candidate)
    ? (candidate as Record<string, unknown>)
    : {};
}

export function OpsMcpTraceTable({ trace }: OpsMcpTraceTableProps) {
  if (!trace || trace.length === 0) {
    return (
      <section className="panel-glow">
        <header className="ops-section-head">
          <h3>MCP 工具调用轨迹</h3>
          <span className="muted">本次请求未触发 MCP 上下文采集</span>
        </header>
        <p className="ops-empty-line">通常发生在原始命令请求或被安全闸门提前拦截时。</p>
      </section>
    );
  }

  const successCount = trace.filter((t) => t.success).length;

  return (
    <section className="panel-glow">
      <header className="ops-section-head">
        <h3>MCP 工具调用轨迹</h3>
        <span className="muted">
          共 {trace.length} 条调用 · 成功 {successCount} / 失败 {trace.length - successCount}
        </span>
      </header>
      <div className="ops-trace-wrap">
        <table className="ops-trace-table">
          <thead>
            <tr>
              <th style={{ width: 36 }}>序号</th>
              <th>MCP 服务</th>
              <th>调用工具</th>
              <th style={{ width: 92 }}>状态</th>
              <th>结果摘要 / 错误</th>
            </tr>
          </thead>
          <tbody>
            {trace.map((t, i) => {
              const args = describeMcpArguments(extractArgs(t), t.tool);
              const toolZh = toolLabelZh(t.tool);
              const hasDetails = args.length > 0;
              return (
                <tr key={`${t.server}-${t.tool}-${i}`} className={t.success ? "is-ok" : "is-err"}>
                  <td className="ops-trace-idx">{i + 1}</td>
                  <td>
                    <span className="ops-trace-server">{t.server}</span>
                  </td>
                  <td>
                    <div className="ops-trace-tool-cell">
                      <span className="ops-trace-tool-zh">{toolZh}</span>
                      <code className="ops-trace-tool" title={t.tool}>
                        {t.tool}
                      </code>
                    </div>
                  </td>
                  <td>
                    {t.success ? (
                      <span className="ops-trace-status ok">✓ 成功</span>
                    ) : (
                      <span className="ops-trace-status err">✕ 失败</span>
                    )}
                  </td>
                  <td>
                    <p className="ops-trace-summary">
                      {t.summary || (t.success ? "—" : "(无摘要)")}
                    </p>
                    {t.error ? <p className="ops-trace-error">⚠ {t.error}</p> : null}
                    {hasDetails ? (
                      <details className="ops-trace-args">
                        <summary>调用参数（{args.length}）</summary>
                        <dl className="ops-trace-args-list">
                          {args.map((a) => (
                            <div key={a.key} className="ops-trace-args-row">
                              <dt>{a.label}</dt>
                              <dd>
                                <code>{a.value}</code>
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </details>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
