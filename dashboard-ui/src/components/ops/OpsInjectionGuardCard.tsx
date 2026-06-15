import type { OpsPromptInjectionEnvelope } from "../../types/ops";
import { OpsDecisionBadge, OpsRiskBadge } from "./OpsStatusBadge";
import { riskZh } from "../../utils/humanReadable/zh/risk";

interface OpsInjectionGuardCardProps {
  envelope?: OpsPromptInjectionEnvelope;
}

// Card visualising the prompt-injection guard outcome. Mirrors the
// visual rhythm of OpsSafetyCard so the four-card grid feels uniform.

function tone(decision: string | undefined): "ok" | "warn" | "danger" | "muted" {
  if (!decision) return "muted";
  const d = decision.toUpperCase();
  if (d === "ALLOW") return "ok";
  if (d === "BLOCK") return "danger";
  return "warn";
}

export function OpsInjectionGuardCard({ envelope }: OpsInjectionGuardCardProps) {
  if (!envelope) {
    return (
      <section className="panel-glow ops-safety">
        <header className="ops-section-head">
          <h3>反提示词注入护栏</h3>
          <span className="muted">未提供检测结果</span>
        </header>
      </section>
    );
  }

  const t = tone(envelope.decision);
  const patterns = envelope.matchedPatterns ?? [];
  const reasonText = envelope.reasonZh || envelope.reason;

  return (
    <section className={`panel-glow ops-safety frame-${t}`}>
      <header className="ops-section-head">
        <h3>反提示词注入护栏</h3>
        <div className="ops-pill-row">
          <OpsDecisionBadge decision={envelope.decision} />
          <OpsRiskBadge risk={envelope.riskLevel} />
        </div>
      </header>

      {reasonText ? (
        <p className="ops-card-reason">{reasonText}</p>
      ) : (
        <p className="ops-card-reason muted">未提供具体原因。</p>
      )}

      {patterns.length > 0 ? (
        <div className="ops-rules">
          <h4>命中注入特征 · {patterns.length}</h4>
          <ul>
            {patterns.map((p, i) => (
              <li
                key={`${p.ruleId}-${i}`}
                className={`ops-rule-item tone-${
                  p.risk?.toUpperCase() === "CRITICAL" || p.risk?.toUpperCase() === "HIGH"
                    ? "danger"
                    : "warn"
                }`}
              >
                <div className="ops-rule-head">
                  <code className="ops-rule-id">{p.ruleId}</code>
                  <span className="ops-rule-decision">注入特征</span>
                  <span className="ops-rule-risk">{riskZh(p.risk)}</span>
                </div>
                {p.description ? <p className="ops-rule-desc">{p.description}</p> : null}
                {p.sample ? (
                  <p className="ops-rule-matched">
                    <span className="muted">命中片段：</span>
                    <code>{p.sample}</code>
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="ops-empty-line muted">
          未命中任何注入规则。反注入护栏作为流水线第一道闸，确保用户输入不会被伪造的系统指令劫持。
        </p>
      )}
    </section>
  );
}
