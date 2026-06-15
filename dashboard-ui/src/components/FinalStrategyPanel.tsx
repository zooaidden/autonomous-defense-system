import type { CoordinatorDecision, FinalStrategy } from "../types";
import {
  strategyStatusZh,
  riskZh,
  actionZh,
  threatZh,
} from "../utils/humanReadable";

interface FinalStrategyPanelProps {
  decision: CoordinatorDecision;
  title?: string;
}

// 把秒级 TTL 转成分钟级人类可读字符串
function formatTtl(strategy: FinalStrategy): string {
  if (strategy.ttl_minutes != null) {
    return `${strategy.ttl_minutes} 分钟 (${strategy.ttl ?? "?"}s)`;
  }
  if (strategy.ttl != null) {
    const minutes = Math.floor(strategy.ttl / 60);
    return `${minutes} 分钟 (${strategy.ttl}s)`;
  }
  return "未设置";
}

// 取主导动作的展示字符串：优先 spec 单数字段，否则回退 actions[0]
function formatAction(strategy: FinalStrategy): string {
  if (strategy.action) return strategy.action;
  return strategy.actions?.[0]?.type ?? "未知";
}

function formatTarget(strategy: FinalStrategy): string {
  if (strategy.target) return strategy.target;
  return strategy.actions?.[0]?.target ?? "—";
}

function statusBadgeClass(status: string): string {
  if (status === "approved_for_execution") return "badge ok";
  if (status === "rejected" || status === "needs_revision") return "badge err";
  return "badge warn";
}

function riskBadgeClass(level: string): string {
  if (level === "low") return "badge ok";
  if (level === "high" || level === "critical") return "badge err";
  return "badge warn";
}

export function FinalStrategyPanel({
  decision,
  title = "最终策略",
}: FinalStrategyPanelProps) {
  const fs = decision.final_strategy;
  const impact = fs.strategy_impact;
  return (
    <div className="panel">
      <div className="strategy-panel-header">
        <h3>{title}</h3>
        <div className="strategy-badges">
          <span className={statusBadgeClass(fs.status)}>{strategyStatusZh(fs.status)}</span>
          <span className={riskBadgeClass(decision.risk_level)}>
            综合风险：{riskZh(decision.risk_level)}
          </span>
        </div>
      </div>

      <div className="strategy-grid">
        <div>
          <span className="strategy-label">策略编号</span>
          <span className="strategy-value">{fs.strategy_id ?? fs.strategyId}</span>
        </div>
        <div>
          <span className="strategy-label">主导动作</span>
          <span className="strategy-value">{actionZh(formatAction(fs))}</span>
        </div>
        <div>
          <span className="strategy-label">作用目标</span>
          <span className="strategy-value">{formatTarget(fs)}</span>
        </div>
        <div>
          <span className="strategy-label">生效时长</span>
          <span className="strategy-value">{formatTtl(fs)}</span>
        </div>
        <div>
          <span className="strategy-label">置信度</span>
          <span className="strategy-value">
            {fs.confidence != null ? `${(fs.confidence * 100).toFixed(0)}%` : "—"}
          </span>
        </div>
        <div>
          <span className="strategy-label">是否放行</span>
          <span className="strategy-value">{fs.approved ? "✓ 已放行" : "✗ 未放行"}</span>
        </div>
        {fs.threatType ? (
          <div>
            <span className="strategy-label">威胁类型</span>
            <span className="strategy-value">{threatZh(fs.threatType)}</span>
          </div>
        ) : null}
      </div>

      {impact && (
        <div className="strategy-impact">
          <h4>策略影响评估</h4>
          <div className="strategy-grid">
            <div>
              <span className="strategy-label">影响等级</span>
              <span className="strategy-value">{riskZh(impact.impact_level)}</span>
            </div>
            <div>
              <span className="strategy-label">爆炸半径</span>
              <span className="strategy-value">
                {impact.expected_blast_radius ?? "—"}
              </span>
            </div>
            <div>
              <span className="strategy-label">受影响资产</span>
              <span className="strategy-value">
                {impact.affected_assets.length} 项
              </span>
            </div>
            <div>
              <span className="strategy-label">残余路径</span>
              <span className="strategy-value">
                {impact.residual_path_count}
              </span>
            </div>
          </div>
          {impact.affected_assets.length > 0 && (
            <p className="muted strategy-rationale">
              受影响资产：{impact.affected_assets.join(", ")}
            </p>
          )}
          {impact.rationale && (
            <p className="muted strategy-rationale">{impact.rationale}</p>
          )}
        </div>
      )}

      {fs.execution_constraints && fs.execution_constraints.length > 0 && (
        <div className="strategy-constraints">
          <h4>执行约束</h4>
          <ul>
            {fs.execution_constraints.map((c, idx) => (
              <li key={`${c}-${idx}`}>{c}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
