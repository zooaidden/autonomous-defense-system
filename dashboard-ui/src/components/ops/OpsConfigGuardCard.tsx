import type { OpsConfigGuardEnvelope } from "../../types/ops";
import { OpsDecisionBadge, OpsRiskBadge } from "./OpsStatusBadge";
import { riskZh } from "../../utils/humanReadable/zh/risk";

interface OpsConfigGuardCardProps {
  envelope?: OpsConfigGuardEnvelope;
}

// Card visualising the deterministic system-config guard. Layout mirrors
// the safety / injection cards so the four-card grid stays balanced.

function tone(decision: string | undefined): "ok" | "warn" | "danger" | "muted" {
  if (!decision) return "muted";
  const d = decision.toUpperCase();
  if (d === "ALLOW") return "ok";
  if (d === "BLOCK") return "danger";
  return "warn";
}

export function OpsConfigGuardCard({ envelope }: OpsConfigGuardCardProps) {
  if (!envelope) {
    return (
      <section className="panel-glow ops-safety">
        <header className="ops-section-head">
          <h3>关键配置文件确定性护栏</h3>
          <span className="muted">未提供检测结果</span>
        </header>
      </section>
    );
  }

  const t = tone(envelope.decision);
  const paths = envelope.matchedPaths ?? [];
  const reasonText = envelope.reasonZh || envelope.reason;

  return (
    <section className={`panel-glow ops-safety frame-${t}`}>
      <header className="ops-section-head">
        <h3>关键配置文件确定性护栏</h3>
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

      {envelope.matchedVerb ? (
        <div className="ops-safe-alt">
          <span className="ops-safe-alt-tag">触发写入动作</span>
          <p>
            <code>{envelope.matchedVerb}</code>
          </p>
        </div>
      ) : null}

      {paths.length > 0 ? (
        <div className="ops-rules">
          <h4>命中受保护路径 · {paths.length}</h4>
          <ul>
            {paths.map((p, i) => (
              <li
                key={`${p.label}-${i}`}
                className={`ops-rule-item tone-${
                  p.risk?.toUpperCase() === "CRITICAL" || p.risk?.toUpperCase() === "HIGH"
                    ? "danger"
                    : "warn"
                }`}
              >
                <div className="ops-rule-head">
                  <code className="ops-rule-id">{p.label}</code>
                  <span className="ops-rule-decision">
                    {p.matchedIn === "instruction" ? "指令文本" : "候选命令"}
                  </span>
                  <span className="ops-rule-risk">{riskZh(p.risk)}</span>
                </div>
                {p.snippet ? (
                  <p className="ops-rule-matched">
                    <span className="muted">命中文本：</span>
                    <code>{p.snippet}</code>
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <p className="ops-empty-line muted">
          未触及 /etc/passwd、/etc/shadow、/etc/sudoers、/etc/ssh/sshd_config、/etc/systemd/system/、/boot/、/lib/modules/ 等受保护路径。
        </p>
      )}
    </section>
  );
}
