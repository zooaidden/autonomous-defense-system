import { useEffect, useMemo, useState } from "react";
import {
  fetchOsKnowledgeGraph,
  fetchOsTopologyProbeStatus,
  runOsTopologyProbe,
} from "../api/services";
import type { OsKnowledgeGraph, OsTopologyProbeStatus } from "../types/systemStatus";
import { Button } from "../ui/Button";
import { Chip } from "../ui/Chip";
import { Panel } from "../ui/Panel";

interface OsTopologyProbePanelProps {
  initialStatus?: OsTopologyProbeStatus;
}

export function OsTopologyProbePanel({ initialStatus }: OsTopologyProbePanelProps) {
  const [status, setStatus] = useState<OsTopologyProbeStatus | null>(initialStatus ?? null);
  const [graph, setGraph] = useState<OsKnowledgeGraph | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      const [nextStatus, nextGraph] = await Promise.all([
        fetchOsTopologyProbeStatus(),
        fetchOsKnowledgeGraph(),
      ]);
      if (!cancelled) {
        if (nextStatus) setStatus(nextStatus);
        if (nextGraph) setGraph(nextGraph);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const intervalLabel = useMemo(() => {
    const seconds = status?.intervalSeconds ?? 86400;
    if (seconds % 86400 === 0) return `${seconds / 86400} 天`;
    if (seconds % 3600 === 0) return `${seconds / 3600} 小时`;
    return `${seconds} 秒`;
  }, [status?.intervalSeconds]);

  async function handleRunProbe() {
    setRunning(true);
    setError(null);
    try {
      const res = await runOsTopologyProbe();
      if (!res.success) throw new Error(res.message);
      if (res.data?.status) setStatus(res.data.status);
      if (res.data?.knowledgeGraph) setGraph(res.data.knowledgeGraph);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  const effectiveRunning = running || Boolean(status?.running);
  const nodeSample = (graph?.nodes ?? []).slice(0, 6);
  const edgeSample = (graph?.edges ?? []).slice(0, 6);

  return (
    <Panel
      tone={status?.lastError ? "danger" : effectiveRunning ? "warn" : "info"}
      className="os-topology-panel"
      title="OS 动态拓扑探测"
      subtitle="通过只读 OS MCP 探测进程与网络 Socket，将当前网络环境转换为动态拓扑和知识图谱，并写入 topology-mcp-server 的动态拓扑存储。"
      actions={
        <Button
          variant="primary"
          size="sm"
          onClick={handleRunProbe}
          loading={effectiveRunning}
          disabled={effectiveRunning}
        >
          {effectiveRunning ? "探测中" : "开始手动探测"}
        </Button>
      }
    >
      <div className="os-probe-kpis">
        <div>
          <span>手动探测</span>
          <strong>始终开启</strong>
        </div>
        <div>
          <span>自动探测</span>
          <strong>{status?.autoEnabled ? "已开启" : "未开启"}</strong>
        </div>
        <div>
          <span>自动间隔</span>
          <strong>{intervalLabel}</strong>
        </div>
        <div>
          <span>拓扑规模</span>
          <strong>
            {status?.assetCount ?? 0} 节点 / {status?.edgeCount ?? 0} 边
          </strong>
        </div>
      </div>

      <div className="os-probe-meta">
        <Chip tone={status?.autoEnabled ? "ok" : "neutral"} leadingDot>
          {status?.autoEnabled ? "自动守护开启" : "自动守护关闭"}
        </Chip>
        <Chip tone={status?.lastProbeAt ? "ok" : "warn"} leadingDot>
          {status?.lastProbeAt ? `最近探测 ${new Date(status.lastProbeAt).toLocaleString()}` : "尚未生成动态拓扑"}
        </Chip>
        <code>{status?.dynamicTopologyPath ?? "topology.dynamic.json"}</code>
      </div>

      {error || status?.lastError ? (
        <p className="os-probe-error">探测错误：{error ?? status?.lastError}</p>
      ) : null}

      <div className="os-graph-preview">
        <section>
          <h4>知识图谱节点</h4>
          {nodeSample.length ? (
            <ul>
              {nodeSample.map((node) => (
                <li key={node.id}>
                  <span>{node.label}</span>
                  <code>{node.type}</code>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">暂无节点，点击手动探测生成。</p>
          )}
        </section>
        <section>
          <h4>关系样例</h4>
          {edgeSample.length ? (
            <ul>
              {edgeSample.map((edge, index) => (
                <li key={`${edge.source}-${edge.target}-${index}`}>
                  <span>{edge.type}</span>
                  <code>
                    {edge.source} {"->"} {edge.target}
                  </code>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">暂无关系，探测后显示 RUNS / CONNECTS_TO 等关系。</p>
          )}
        </section>
      </div>
    </Panel>
  );
}
