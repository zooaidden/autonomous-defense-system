import type { OpsSafetyValidation } from "../../types/ops";
import { OpsDecisionBadge, OpsRiskBadge } from "./OpsStatusBadge";
import { decisionZh } from "../../utils/humanReadable/zh/decision";
import { riskZh } from "../../utils/humanReadable/zh/risk";

interface OpsSafetyCardProps {
  validation?: OpsSafetyValidation;
}

function decisionTone(decision: string | undefined): string {
  if (!decision) return "muted";
  const d = decision.toUpperCase();
  if (d === "ALLOW") return "ok";
  if (d === "REQUIRE_APPROVAL") return "warn";
  if (d === "BLOCK") return "danger";
  return "muted";
}

export function OpsSafetyCard({ validation }: OpsSafetyCardProps) {
  if (!validation) {
    return (
      <section className="panel-glow ops-safety">
        <header className="ops-section-head">
          <h3>安全闸门</h3>
          <span className="muted">未提供校验结果</span>
        </header>
      </section>
    );
  }

  const tone = decisionTone(validation.decision);
  const rules = validation.matchedRules ?? [];

  return (
    <section className={`panel-glow ops-safety frame-${tone}`}>
      <header className="ops-section-head">
        <h3>安全闸门 · 指令校验器</h3>
        <div className="ops-pill-row">
          <OpsDecisionBadge decision={validation.decision} />
          <OpsRiskBadge risk={validation.riskLevel} />
        </div>
      </header>

      {validation.reason ? (
        <p className="ops-card-reason">{validation.reason}</p>
      ) : (
        <p className="ops-card-reason muted">未提供具体原因。</p>
      )}

      {validation.safeAlternative ? (
        <div className="ops-safe-alt">
          <span className="ops-safe-alt-tag">建议替代方案</span>
          <p>{validation.safeAlternative}</p>
        </div>
      ) : null}

      {rules.length > 0 ? (
        <div className="ops-rules">
          <h4>命中规则 · {rules.length}</h4>
          <ul>
            {rules.map((r, i) => (
              <li key={`${r.ruleId ?? "rule"}-${i}`} className={`ops-rule-item tone-${decisionTone(r.decision)}`}>
                <div className="ops-rule-head">
                  <code className="ops-rule-id">{r.ruleId ?? "—"}</code>
                  <span className="ops-rule-decision">{r.decision ? decisionZh(r.decision) : "—"}</span>
                  <span className="ops-rule-risk">{r.riskLevel ? riskZh(r.riskLevel) : "—"}</span>
                </div>
                {r.description ? <p className="ops-rule-desc">{r.description}</p> : null}
                {r.matched ? (
                  <p className="ops-rule-matched">
                    <span className="muted">触发文本：</span>
                    <code>{r.matched}</code>
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}
