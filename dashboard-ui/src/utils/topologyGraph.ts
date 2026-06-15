/**
 * Build a simple graph for SVG rendering: nodes + edges + primary chain for highlight animation.
 */

import type { TopologyContextSummary } from "../types";
import type { UnifiedWorkflowBundle } from "./workflowDisplay";
import type { WorkflowRunResult } from "../types/workflow";

export interface TopologyNode {
  id: string;
  label: string;
}

export interface TopologyEdge {
  from: string;
  to: string;
}

export interface TopologyModel {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  /** Ordered walk for highlighting along residual path + assets */
  primaryChain: string[];
}

function uniq(ids: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    const k = id.trim();
    if (!k || seen.has(k)) continue;
    seen.add(k);
    out.push(k);
  }
  return out;
}

/** Extract topology summary from loosely-typed coordinator payloads. */
function pickTopologySummary(bundle: UnifiedWorkflowBundle): TopologyContextSummary | null {
  const cd = bundle.coordinatorDecision as { topology_context_summary?: TopologyContextSummary } | null;
  const fs = bundle.finalStrategy as { topology_context_summary?: TopologyContextSummary } | undefined;
  return cd?.topology_context_summary ?? fs?.topology_context_summary ?? null;
}

export function buildTopologyModel(
  bundle: UnifiedWorkflowBundle,
  workflowRaw: WorkflowRunResult | null,
): TopologyModel {
  const summary = pickTopologySummary(bundle);

  const assets = summary?.affected_assets?.length ? [...summary.affected_assets] : [];
  const paths = summary?.red_team?.residual_attack_paths ?? [];

  let chain: string[] = [];
  if (paths.length && paths[0].nodes?.length) {
    chain = uniq(paths[0].nodes.map(String));
    if (paths[0].source && !chain.includes(paths[0].source)) chain.unshift(paths[0].source);
    if (paths[0].target && !chain.includes(paths[0].target)) chain.push(paths[0].target);
  }

  const ctx = (workflowRaw?.debateState as { securityEvent?: { context?: Record<string, unknown> } } | undefined)
    ?.securityEvent?.context;
  const src =
    ctx && typeof ctx.srcIp === "string"
      ? ctx.srcIp
      : ctx && typeof ctx.source_ip === "string"
        ? ctx.source_ip
        : "";
  const dst =
    ctx && typeof ctx.dstIp === "string"
      ? ctx.dstIp
      : ctx && typeof ctx.target_ip === "string"
        ? ctx.target_ip
        : "";

  if (!chain.length && (src || dst)) {
    chain = uniq([src, dst].filter(Boolean));
  }

  if (!chain.length && assets.length) {
    chain = uniq([...assets]);
  }

  const nodes: TopologyNode[] = uniq([...chain, ...assets]).map((id) => ({
    id,
    label: id.length > 14 ? `${id.slice(0, 12)}…` : id,
  }));

  const edges: TopologyEdge[] = [];
  for (let i = 0; i < chain.length - 1; i++) {
    edges.push({ from: chain[i], to: chain[i + 1] });
  }

  return {
    nodes,
    edges,
    primaryChain: chain.length ? chain : nodes.map((n) => n.id),
  };
}

/** How many nodes along primaryChain should be treated as "visited" at this debate step. */
export function highlightChainDepth(stepIndex: number, chainLen: number): number {
  if (chainLen <= 0) return 0;
  return Math.min(chainLen, Math.max(1, stepIndex + 2));
}
