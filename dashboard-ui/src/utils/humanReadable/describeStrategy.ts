// CoordinatorDecision + final_strategy → 1-3 short Chinese sentences.

import type { CoordinatorDecision } from "../../types";
import { threatZh } from "./zh/threat";
import { strategyStatusZh } from "./zh/decision";
import { riskZh } from "./zh/risk";

export function describeCoordinatorDecisionHuman(cd: CoordinatorDecision): string[] {
  const lines: string[] = [];
  const reasoning = (cd.decision_reasoning ?? "").trim();
  if (reasoning) {
    lines.push(`协调器结论摘要：${reasoning}`);
  }
  lines.push(
    `策略状态：${strategyStatusZh(cd.status)}；综合风险等级：${riskZh(cd.risk_level)}。`,
  );
  if (cd.human_approval_required) {
    lines.push("需要人工审批后方可自动执行（符合高风险或策略边界提示）。");
  } else {
    lines.push("当前无需额外人工审批即可继续自动化链路（仍以全局护栏为准）。");
  }
  return lines;
}

export function describeFinalStrategyHuman(fs: Record<string, unknown>): string[] {
  const sid = String(fs.strategyId ?? fs.strategy_id ?? "");
  const threat = String(fs.threatType ?? fs.threat_type ?? "");
  const layer = String(fs.targetLayer ?? fs.target_layer ?? "");
  const ttl = typeof fs.ttl === "number" ? fs.ttl : Number(fs.ttl ?? 0);
  const conf = typeof fs.confidence === "number" ? fs.confidence : Number(fs.confidence ?? 0);
  const actions = Array.isArray(fs.actions) ? fs.actions : [];
  const lines: string[] = [];
  lines.push(
    `策略编号 ${sid || "—"}：面向「${threatZh(threat) || "未知威胁"}」场景，作用层级 ${layer || "—"}，置信度约 ${(conf * 100).toFixed(0)}%。`,
  );
  if (ttl > 0)
    lines.push(`建议生效时长约 ${Math.round(ttl / 60)} 分钟（${ttl} 秒），到期应按预案复核或续期。`);
  if (actions.length === 0) {
    lines.push("尚未列出具体处置动作，请回到上游代理补齐动作清单。");
  } else {
    lines.push(
      `共包含 ${actions.length} 条处置动作，优先顺序与流量路径一致（可在右侧拓扑联动理解）。`,
    );
  }
  const rationale = String(fs.rationale ?? "").trim();
  if (rationale) lines.push(`策略要点：${rationale}`);
  return lines;
}
