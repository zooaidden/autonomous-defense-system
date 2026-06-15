import { useId, useMemo } from "react";
import type { TopologyEdge, TopologyModel } from "../../utils/topologyGraph";

interface TopologyStoryboardProps {
  model: TopologyModel;
  activeDepth: number;
}

function layoutChain(chain: string[], width: number, height: number): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  const n = chain.length;
  if (!n) return positions;
  const pad = 36;
  const usableW = width - pad * 2;
  const usableH = height - pad * 2;
  if (n === 1) {
    positions.set(chain[0], { x: width / 2, y: height / 2 });
    return positions;
  }
  chain.forEach((id, i) => {
    const t = n === 1 ? 0.5 : i / (n - 1);
    const x = pad + t * usableW;
    const wave = Math.sin(t * Math.PI) * (usableH * 0.22);
    const y = height / 2 + wave;
    positions.set(id, { x, y });
  });
  return positions;
}

function edgeKey(a: string, b: string): string {
  return `${a}|${b}`;
}

export function TopologyStoryboard({ model, activeDepth }: TopologyStoryboardProps) {
  const { nodes, edges, primaryChain } = model;
  const markerUid = useId().replace(/:/g, "");
  const markerId = `arrow-${markerUid}`;

  const layout = useMemo(() => {
    const w = 280;
    const h = 220;
    const chain = primaryChain.length ? primaryChain : nodes.map((n) => n.id);
    const pos = layoutChain(chain, w, h);
    const orphan = nodes.filter((n) => !pos.has(n.id));
    orphan.forEach((n, i) => {
      pos.set(n.id, { x: 40 + (i % 3) * 70, y: 160 + Math.floor(i / 3) * 36 });
    });
    return { pos, w, h };
  }, [nodes, primaryChain]);

  const litNodes = useMemo(() => {
    const chain = primaryChain.length ? primaryChain : nodes.map((n) => n.id);
    const depth = Math.min(activeDepth, chain.length);
    return new Set(chain.slice(0, Math.max(0, depth)));
  }, [primaryChain, nodes, activeDepth]);

  const litEdges = useMemo(() => {
    const chain = primaryChain.length ? primaryChain : nodes.map((n) => n.id);
    const depth = Math.min(activeDepth, chain.length);
    const set = new Set<string>();
    for (let i = 0; i < depth - 1 && i < chain.length - 1; i++) {
      set.add(edgeKey(chain[i], chain[i + 1]));
    }
    return set;
  }, [primaryChain, activeDepth, nodes]);

  const edgeList: TopologyEdge[] =
    edges.length > 0
      ? edges
      : (() => {
          const chain = primaryChain.length ? primaryChain : [];
          const e: TopologyEdge[] = [];
          for (let i = 0; i < chain.length - 1; i++) {
            e.push({ from: chain[i], to: chain[i + 1] });
          }
          return e;
        })();

  return (
    <div className="topology-storyboard">
      <p className="topology-caption muted">
        示意拓扑：高亮段表示当前回合推演到的策略影响路径（随对话回放同步）。
      </p>
      <svg className="topology-svg" viewBox={`0 0 ${layout.w} ${layout.h}`} aria-hidden>
        <defs>
          <marker id={markerId} markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 z" fill="#5eead4" opacity={0.85} />
          </marker>
        </defs>
        {edgeList.map((e, i) => {
          const p1 = layout.pos.get(e.from);
          const p2 = layout.pos.get(e.to);
          if (!p1 || !p2) return null;
          const active = litEdges.has(edgeKey(e.from, e.to));
          return (
            <line
              key={`${e.from}-${e.to}-${i}`}
              x1={p1.x}
              y1={p1.y}
              x2={p2.x}
              y2={p2.y}
              className={`topology-edge-line ${active ? "is-lit" : ""}`}
              markerEnd={`url(#${markerId})`}
            />
          );
        })}
        {nodes.map((n) => {
          const p = layout.pos.get(n.id);
          if (!p) return null;
          const on = litNodes.has(n.id);
          return (
            <g key={n.id} transform={`translate(${p.x}, ${p.y})`}>
              <circle r={on ? 16 : 13} className={`topology-node-circle ${on ? "is-lit" : ""}`} />
              <text textAnchor="middle" dy={4} className="topology-node-label">
                {n.label}
              </text>
            </g>
          );
        })}
      </svg>
      {!nodes.length && (
        <p className="muted topology-fallback">暂无拓扑节点数据；可在事件中附带残余路径或受影响资产后展示。</p>
      )}
    </div>
  );
}
