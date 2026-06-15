// MCP trace panel — renders the trace returned by topology/policy/os MCP
// servers. Arguments are rendered via humanReadable.describeMcpArguments so
// the UI never exposes raw JSON.

import type { MCPToolCall } from "../types";
import { Chip } from "../ui/Chip";
import { describeMcpArguments, toolLabelZh } from "../utils/humanReadable/describeMcp";

interface McpTracePanelProps {
  trace: MCPToolCall[];
  title?: string;
}

const EMPTY_HINT = "本次决策未触发 MCP 工具调用。";

function formatTimestamp(value?: string): string {
  if (!value) return "";
  const ts = new Date(value);
  if (Number.isNaN(ts.getTime())) return value;
  return ts.toLocaleString();
}

export function McpTracePanel({ trace, title = "MCP 工具调用链" }: McpTracePanelProps) {
  return (
    <div className="panel">
      <div className="mcp-trace-header">
        <h3>{title}</h3>
        {trace.length > 0 && <span className="muted">共 {trace.length} 次调用</span>}
      </div>
      {trace.length === 0 ? (
        <p className="mcp-empty">{EMPTY_HINT}</p>
      ) : (
        <ol className="mcp-trace">
          {trace.map((call, idx) => {
            const args = describeMcpArguments(call.arguments, call.tool);
            return (
              <li key={`${call.server}-${call.tool}-${idx}`} className="mcp-call">
                <div className="mcp-call-header">
                  <span className="mcp-call-title">
                    <span className="mcp-server">{call.server}</span>
                    <span className="muted"> · </span>
                    <span className="mcp-tool">{toolLabelZh(call.tool)}</span>
                  </span>
                  <Chip tone={call.success ? "ok" : "danger"} leadingDot>
                    {call.success ? "成功" : "失败"}
                  </Chip>
                </div>
                {(call.summary || call.elapsedMs != null || call.timestamp) && (
                  <div className="mcp-call-meta">
                    {call.summary && <p className="mcp-call-summary">{call.summary}</p>}
                    <div className="mcp-call-meta-row">
                      {call.elapsedMs != null && (
                        <span className="muted">耗时 {call.elapsedMs}ms</span>
                      )}
                      {call.timestamp && (
                        <span className="muted">
                          {call.elapsedMs != null ? " · " : ""}
                          {formatTimestamp(call.timestamp)}
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {args.length > 0 ? (
                  <div className="mcp-call-args-block">
                    <span className="muted mcp-call-args-label">调用参数</span>
                    <dl className="mcp-args-dl">
                      {args.map((arg) => (
                        <div key={arg.key}>
                          <dt>{arg.label}</dt>
                          <dd>{arg.value}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                ) : (
                  <p className="muted mcp-call-noargs">无显式参数（工具内部按上下文推断）</p>
                )}
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}
