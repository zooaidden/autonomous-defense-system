// MCP tool call helpers: short Chinese summary + structured argument readers.

import type { MCPToolCall } from "../../types";

// Map known MCP tool ids to their Chinese, business-friendly names.
const TOOL_LABEL_ZH: Record<string, string> = {
  validate_strategy: "策略合规校验",
  get_asset_info: "资产画像查询",
  find_paths: "拓扑路径探测",
  get_topology_snapshot: "拓扑快照",
  get_process_list: "进程列表",
  get_network_sockets: "网络连接",
  get_open_files: "已打开文件",
  get_system_logs: "系统日志",
  get_disk_usage: "磁盘使用",
  get_memory_status: "内存状态",
  get_cpu_load: "CPU 负载",
  get_uptime: "系统运行时长",
  get_service_status: "服务状态",
  // Topology / policy MCP tools for completeness.
  get_neighbors: "邻居资产",
  get_critical_assets: "关键资产",
  check_connectivity: "连通性",
  evaluate_strategy_impact: "策略影响",
  check_business_constraints: "业务约束",
  require_human_approval: "人工审批",
  suggest_safer_strategy: "安全替代方案",
};

export function toolLabelZh(tool: string): string {
  return TOOL_LABEL_ZH[tool] ?? tool;
}

export function describeMcpCallHuman(call: MCPToolCall): string {
  const ok = call.success ? "成功" : "失败";
  const summary = (call.summary ?? "").trim();
  const base = `${call.server} · ${toolLabelZh(call.tool)} → ${ok}`;
  return summary ? `${base}（${summary}）` : base;
}

// Stringify a single MCP argument value into a readable label.
function argValueText(value: unknown): string {
  if (value == null) return "—";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (Array.isArray(value)) return value.map((v) => argValueText(v)).join(", ");
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return Object.prototype.toString.call(value);
    }
  }
  return String(value);
}

// Human-readable rendering of MCP tool arguments. Returns key/value pairs so
// callers can render them as a description list instead of dumping raw JSON.
const ARG_LABEL_ZH: Record<string, string> = {
  ip_or_asset_id: "目标资产",
  asset_id: "资产编号",
  source: "起点",
  target: "终点",
  max_depth: "最大跳数",
  strategyId: "策略编号",
  strategy_id: "策略编号",
  policyId: "策略编号",
  service_name: "服务名",
  port: "端口",
  pid: "进程号",
  user: "用户",
  limit: "条数",
  duration: "持续时长",
  tail: "最近条数",
  namespace: "命名空间",
  cluster: "集群",
  region: "区域",
};

export interface McpArgumentEntry {
  key: string;
  label: string;
  value: string;
}

export function describeMcpArguments(
  args?: Record<string, unknown>,
  _tool?: string,
): McpArgumentEntry[] {
  if (!args || Object.keys(args).length === 0) return [];
  return Object.entries(args).map(([key, value]) => ({
    key,
    label: ARG_LABEL_ZH[key] ?? key,
    value: argValueText(value),
  }));
}
