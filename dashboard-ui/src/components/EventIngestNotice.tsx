import { useEffect, useState } from "react";
import { fetchEventIngestStatus } from "../api/services";
import type { EventIngestStatus } from "../types/systemStatus";
import { Chip } from "../ui/Chip";
import { Panel } from "../ui/Panel";

export function EventIngestNotice() {
  const [status, setStatus] = useState<EventIngestStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    void fetchEventIngestStatus().then((next) => {
      if (!cancelled) setStatus(next);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const enabled = status?.enabled ?? false;
  const running = status?.running ?? false;
  const tone = running ? "ok" : enabled ? "warn" : "info";

  return (
    <Panel
      tone={tone}
      className="event-ingest-notice"
      title="真实事件感知"
      subtitle="系统现在支持从 defense-gateway 发布到 Kafka 的真实安全事件自动进入 agent-brain 工作流；Sandbox 演示事件仍保留为手动验证入口。"
      actions={
        <Chip tone={running ? "ok" : enabled ? "warn" : "info"} leadingDot>
          {running ? "Kafka 感知运行中" : enabled ? "已启用，等待连接" : "未启用"}
        </Chip>
      }
    >
      <div className="event-ingest-grid">
        <div>
          <span className="event-ingest-label">真实事件入口</span>
          <strong>{status?.topic ?? "security.events"}</strong>
        </div>
        <div>
          <span className="event-ingest-label">Kafka 地址</span>
          <strong>{status?.bootstrapServers ?? "localhost:9092"}</strong>
        </div>
        <div>
          <span className="event-ingest-label">已处理</span>
          <strong>{status?.processedCount ?? 0}</strong>
        </div>
        <div>
          <span className="event-ingest-label">最近事件</span>
          <strong>{status?.lastEventId ?? "暂无"}</strong>
        </div>
      </div>
      {status?.lastError ? (
        <p className="event-ingest-error">最近错误：{status.lastError}</p>
      ) : null}
      <p className="event-ingest-note">
        开启方式：启动 agent-brain 前设置 <code>ENABLE_KAFKA_EVENT_INGEST=true</code>。
        真实事件由网关接入，演示事件仍可通过 Sandbox 按钮生成。
      </p>
    </Panel>
  );
}
