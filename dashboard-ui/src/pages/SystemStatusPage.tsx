// System status page (/system) — aggregates platform metadata, service
// health hints, MCP plugin catalogue, executor whitelist and guardrail
// state. Backed by GET /system/status from agent-brain.

import { useEffect, useState } from "react";
import { AGENT_BRAIN_BASE_URL, USE_MOCK_DATA } from "../api/config";
import { Chip } from "../ui/Chip";
import { toolLabelZh } from "../utils/humanReadable/describeMcp";
import type {
  SystemMcpClient,
  SystemServiceEntry,
  SystemStatusResponse,
} from "../types/systemStatus";
import "../styles/ops.css";

const MOCK_STATUS: SystemStatusResponse = {
  platform: {
    system: "Linux",
    release: "5.10.0-1.0.13.kos1.loongarch64",
    version: "#1 SMP Tue Apr 11 18:21:23 UTC 2026",
    machine: "loongarch64",
    node: "kylin-loong-1",
    hostname: "kylin-loong-1",
    python: "3.12.3",
    kylinVersion: "Kylin Linux Advanced Server release V11 (Sword)",
    osPretty: "Kylin Linux Advanced Server V11",
    isLoongArch: true,
  },
  services: [
    { name: "agent-brain", port: 8001, status: "up" },
    { name: "defense-gateway", port: 8080, status: "unknown" },
    { name: "actuator-service", port: 8002, status: "unknown" },
    { name: "formal-verifier", port: 8081, status: "unknown" },
    { name: "dashboard-ui", port: 5173, status: "unknown" },
  ],
  mcpClients: {
    topology: {
      enabled: true,
      mode: "real",
      serverPath: "~/autonomous-defense-system/mcp-servers/topology-mcp-server",
      tools: [
        "get_asset_info",
        "get_neighbors",
        "get_critical_assets",
        "find_paths",
        "check_connectivity",
        "evaluate_strategy_impact",
      ],
    },
    policy: {
      enabled: true,
      mode: "real",
      serverPath: "~/autonomous-defense-system/mcp-servers/policy-mcp-server",
      tools: [
        "validate_strategy",
        "check_business_constraints",
        "require_human_approval",
        "suggest_safer_strategy",
      ],
    },
    os: {
      enabled: true,
      mode: "local",
      serverPath: "~/autonomous-defense-system/mcp-servers/os-mcp-server",
      mcpSdkInstalled: true,
      tools: [
        "get_process_list",
        "get_network_sockets",
        "get_open_files",
        "get_system_logs",
        "get_disk_usage",
        "get_memory_status",
        "get_cpu_load",
        "get_uptime",
        "get_service_status",
      ],
    },
    actuator: {
      enabled: false,
      mode: "http-fallback",
      serverPath: null,
      note: "actuator-mcp-server packaged but agent-brain uses HTTP actuator client in /workflow/run",
    },
  },
  executor: {
    whitelist: ["df", "free", "journalctl", "lsof", "netstat", "ps", "ss", "systemctl", "uptime"],
    policy: "least-privilege (read-only diagnostics only)",
  },
  guards: {
    promptInjectionEnabled: true,
    systemConfigGuardEnabled: true,
    intentValidatorEnabled: true,
  },
  auditFile: {
    enabled: true,
    directory: "~/autonomous-defense-system/logs/audit",
  },
};

const SERVICE_LABEL: Record<string, string> = {
  "agent-brain": "推理大脑",
  "defense-gateway": "防御网关",
  "actuator-service": "执行器服务",
  "formal-verifier": "形式化验证器",
  "dashboard-ui": "前端控制台",
};

const MCP_LABEL: Record<string, string> = {
  topology: "拓扑 MCP",
  policy: "策略 MCP",
  os: "OS 状态 MCP",
  actuator: "执行器 MCP",
};

function serviceTone(status: string): "ok" | "warn" | "danger" | "neutral" | "info" {
  if (status === "up") return "ok";
  if (status === "down") return "danger";
  return "neutral";
}

function platformIcon(machine: string): string {
  const m = machine.toLowerCase();
  if (m.includes("loong")) return "龍";
  if (m.includes("x86") || m.includes("amd64")) return "x86";
  if (m.includes("arm") || m.includes("aarch")) return "ARM";
  return "·";
}

export function SystemStatusPage() {
  const [data, setData] = useState<SystemStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch(`${AGENT_BRAIN_BASE_URL}/system/status`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const json = (await res.json()) as SystemStatusResponse;
        if (!cancelled) setData(json);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        if (USE_MOCK_DATA) {
          if (!cancelled) {
            setData(MOCK_STATUS);
            setError(`无法连接 agent-brain（${msg}），已自动切换至本地 mock。`);
          }
        } else if (!cancelled) {
          setError(`无法获取系统状态：${msg}`);
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  if (!data) {
    return (
      <section className="ops-page">
        <header className="ops-hero">
          <div className="ops-hero-text">
            <span className="ops-hero-eyebrow">A2 · 部署与平台姿态</span>
            <h1 className="ops-hero-title">系统状态</h1>
            <p className="ops-hero-sub">
              {error ?? "正在从 agent-brain GET /system/status 拉取平台信息…"}
            </p>
          </div>
        </header>
      </section>
    );
  }

  return (
    <section className="ops-page sys-page">
      <header className="ops-hero">
        <div className="ops-hero-text">
          <span className="ops-hero-eyebrow">A2 · 部署与平台姿态</span>
          <h1 className="ops-hero-title">系统状态</h1>
          <p className="ops-hero-sub">
            一站式查看 LoongArch 麒麟主机平台、各服务进程、MCP 插件目录与最小权限执行器白名单，
            支撑 B/S 架构 + 国产化运行环境的可观测性。
          </p>
        </div>
        <div className="ops-hero-meta">
          <div className="ops-hero-meta-item">
            <span className="ops-hero-meta-label">数据源</span>
            <code className="ops-hero-meta-value">{AGENT_BRAIN_BASE_URL}/system/status</code>
          </div>
        </div>
      </header>

      {error ? <p className="sys-warning">{error}</p> : null}

      <article className="panel-glow sys-platform">
        <header className="ops-section-head">
          <h3>平台信息</h3>
          <div className="ops-pill-row">
            <Chip tone="info" leadingDot>
              架构 · {platformIcon(data.platform.machine)} {data.platform.machine}
            </Chip>
            {data.platform.isLoongArch ? (
              <Chip tone="warn" leadingDot>
                龙芯 LoongArch
              </Chip>
            ) : null}
          </div>
        </header>
        <dl className="sys-platform-grid">
          <div>
            <dt>操作系统</dt>
            <dd>{data.platform.osPretty ?? data.platform.system}</dd>
          </div>
          {data.platform.kylinVersion ? (
            <div>
              <dt>麒麟版本</dt>
              <dd>{data.platform.kylinVersion}</dd>
            </div>
          ) : null}
          <div>
            <dt>内核</dt>
            <dd>
              <code>{data.platform.release}</code>
            </dd>
          </div>
          <div>
            <dt>主机名</dt>
            <dd>{data.platform.hostname}</dd>
          </div>
          <div>
            <dt>Python 运行时</dt>
            <dd>{data.platform.python}</dd>
          </div>
        </dl>
      </article>

      <article className="panel-glow">
        <header className="ops-section-head">
          <h3>服务进程</h3>
          <span className="muted">共 {data.services.length} 项</span>
        </header>
        <div className="sys-service-grid">
          {data.services.map((svc) => (
            <ServiceTile key={svc.name} svc={svc} />
          ))}
        </div>
      </article>

      <article className="panel-glow">
        <header className="ops-section-head">
          <h3>MCP 插件目录</h3>
          <span className="muted">
            {Object.keys(data.mcpClients).length} 个 MCP 客户端，按服务分组
          </span>
        </header>
        <div className="sys-mcp-grid">
          {Object.entries(data.mcpClients).map(([key, client]) => (
            <McpTile key={key} mcpKey={key} client={client} />
          ))}
        </div>
      </article>

      <article className="panel-glow">
        <header className="ops-section-head">
          <h3>最小权限执行器</h3>
          <span className="muted">{data.executor.policy ?? "least-privilege"}</span>
        </header>
        <p className="sys-exec-hint muted">
          只有以下白名单中的二进制可被执行器调用，且默认仅支持只读子命令，从根本上杜绝任意命令注入。
        </p>
        <div className="sys-chip-row">
          {data.executor.whitelist.map((cmd) => (
            <code key={cmd} className="sys-cmd-chip">
              {cmd}
            </code>
          ))}
        </div>
      </article>

      {data.guards ? (
        <article className="panel-glow">
          <header className="ops-section-head">
            <h3>护栏总览</h3>
            <span className="muted">用于答辩的「确定性 + 最小权限」事实表</span>
          </header>
          <ul className="sys-guard-list">
            <li>
              <Chip tone={data.guards.promptInjectionEnabled ? "ok" : "neutral"} leadingDot>
                {data.guards.promptInjectionEnabled ? "已启用" : "未启用"}
              </Chip>
              反提示词注入护栏
            </li>
            <li>
              <Chip tone={data.guards.systemConfigGuardEnabled ? "ok" : "neutral"} leadingDot>
                {data.guards.systemConfigGuardEnabled ? "已启用" : "未启用"}
              </Chip>
              关键配置文件确定性护栏
            </li>
            <li>
              <Chip tone={data.guards.intentValidatorEnabled ? "ok" : "neutral"} leadingDot>
                {data.guards.intentValidatorEnabled ? "已启用" : "未启用"}
              </Chip>
              意图安全校验器
            </li>
          </ul>
        </article>
      ) : null}

      {data.auditFile ? (
        <article className="panel-glow">
          <header className="ops-section-head">
            <h3>审计落盘目录</h3>
            <Chip tone={data.auditFile.enabled ? "ok" : "neutral"} leadingDot>
              {data.auditFile.enabled ? "已启用" : "已禁用"}
            </Chip>
          </header>
          <code className="sys-audit-path">{data.auditFile.directory}</code>
          <p className="muted sys-audit-hint">
            每个 /ops/chat 与 /workflow/run 请求都会在该目录下生成 audit-&lt;requestId&gt;.json，
            支持通过 <code>GET /audit/{"{requestId}"}</code> 端点下载完整 JSON。
          </p>
        </article>
      ) : null}
    </section>
  );
}

function ServiceTile({ svc }: { svc: SystemServiceEntry }) {
  const tone = serviceTone(svc.status);
  const labelZh = SERVICE_LABEL[svc.name] ?? svc.name;
  // Chip tone is a subset that excludes "info" because services either
  // map cleanly to ok/danger/neutral here. Coerce to make the type happy.
  const chipTone: "ok" | "danger" | "neutral" =
    tone === "ok" ? "ok" : tone === "danger" ? "danger" : "neutral";
  return (
    <div className={`sys-service-tile tone-${tone}`}>
      <div className="sys-service-head">
        <span className="sys-service-name">{labelZh}</span>
        <Chip tone={chipTone} leadingDot>
          {svc.status === "up"
            ? "在线"
            : svc.status === "down"
              ? "离线"
              : "未知"}
        </Chip>
      </div>
      <p className="sys-service-meta">
        端口 <code>{svc.port}</code> · <code>{svc.name}</code>
      </p>
    </div>
  );
}

function McpTile({ mcpKey, client }: { mcpKey: string; client: SystemMcpClient }) {
  const labelZh = MCP_LABEL[mcpKey] ?? mcpKey;
  const tone: "ok" | "neutral" = client.enabled ? "ok" : "neutral";
  return (
    <div className={`sys-mcp-tile tone-${tone}`}>
      <header className="sys-mcp-head">
        <span className="sys-mcp-name">{labelZh}</span>
        <Chip tone={tone} leadingDot>
          {client.enabled ? `已接入 · ${client.mode}` : "未启用"}
        </Chip>
      </header>
      {client.serverPath ? (
        <p className="sys-mcp-path">
          <span className="muted">服务路径：</span>
          <code title={client.serverPath}>{client.serverPath}</code>
        </p>
      ) : null}
      {client.note ? <p className="muted sys-mcp-note">{client.note}</p> : null}
      {client.tools && client.tools.length > 0 ? (
        <div className="sys-mcp-tools">
          {client.tools.map((t) => (
            <span key={t} className="sys-mcp-tool" title={t}>
              {toolLabelZh(t)}
            </span>
          ))}
        </div>
      ) : null}
    </div>
  );
}
