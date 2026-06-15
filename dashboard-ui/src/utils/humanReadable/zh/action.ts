// Chinese localization for action types emitted by Planner/Coordinator strategies
// and for the OPS intent action verbs (subset overlaps with security defense).

export const ACTION_ZH: Record<string, string> = {
  BLOCK_IP: "封禁 IP",
  ALLOW_IP: "放行 IP",
  ISOLATE_POD: "隔离 Pod",
  ISOLATE_HOST: "隔离主机",
  RESTRICT_EGRESS: "限制出站",
  RESTRICT_INGRESS: "限制入站",
  DROP_TRAFFIC: "丢弃流量",
  QUARANTINE: "隔离至检疫区",
  REVOKE_TOKEN: "撤销凭据",
  KILL_PROCESS: "终止进程",
  KILL_SESSION: "终止会话",
  RATE_LIMIT: "限速",
  SCALE_DOWN: "缩容",
  ROLLBACK: "回滚",
  ALERT_ONLY: "仅告警",
  PATCH: "应用补丁",
  SNAPSHOT: "建立快照",
  COLLECT_EVIDENCE: "取证收集",
};

export function actionZh(value?: string | null): string {
  if (!value) return "—";
  return ACTION_ZH[String(value).toUpperCase()] ?? String(value);
}

// Common security event action verbs (lower-case in mock data).
export const EVENT_ACTION_ZH: Record<string, string> = {
  spawn_shell: "启动 Shell",
  http_request: "HTTP 请求",
  anomalous_connection: "异常连接",
  credential_dump: "凭据导出",
  port_scan: "端口扫描",
  file_write: "文件写入",
  registry_modify: "注册表修改",
  process_inject: "进程注入",
  privilege_escalation: "权限提升",
  lateral_login: "横向登录",
};

export function eventActionZh(value?: string | null): string {
  if (!value) return "—";
  return EVENT_ACTION_ZH[String(value)] ?? String(value);
}
