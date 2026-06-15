import type { OpsChatResponse } from "../../types/ops";
import { OpsDecisionBadge, OpsRiskBadge } from "./OpsStatusBadge";

interface OpsResultHeaderProps {
  result: OpsChatResponse;
  source: "live" | "mock";
}

export function OpsResultHeader({ result, source }: OpsResultHeaderProps) {
  const intentLabel = result.intentLabel ?? result.intent;
  return (
    <section className="panel-glow ops-result-head">
      <div className="ops-result-head-meta">
        <div className="ops-result-head-meta-row">
          <span className="ops-result-meta-tag">请求编号</span>
          <code className="ops-result-meta-id">{result.requestId}</code>
          <span className={`ops-source-tag ${source === "mock" ? "is-mock" : "is-live"}`}>
            {source === "mock" ? "本地示例" : "实时调用"}
          </span>
        </div>
        <div className="ops-result-head-meta-row">
          <span className="ops-result-meta-tag">指令意图</span>
          <span className="ops-result-meta-intent">{intentLabel}</span>
          <span className="muted">（{result.intent}）</span>
        </div>
      </div>

      <div className="ops-result-head-pills">
        <OpsRiskBadge risk={result.riskLevel} size="lg" />
        <OpsDecisionBadge decision={result.decision} size="lg" />
      </div>

      <div className="ops-final-answer">
        <span className="ops-final-answer-label">最终回答</span>
        <p>{result.finalAnswer}</p>
      </div>
    </section>
  );
}
