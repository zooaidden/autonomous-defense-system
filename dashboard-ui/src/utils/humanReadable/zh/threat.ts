// Chinese localization for threat type labels emitted by Planner/Coordinator.

export const THREAT_ZH: Record<string, string> = {
  LATERAL_MOVEMENT: "横向移动",
  DATA_EXFILTRATION: "数据外泄",
  PRIVILEGE_ESCALATION: "权限提升",
  CREDENTIAL_ACCESS: "凭据窃取",
  PERSISTENCE: "驻留",
  EXECUTION: "执行",
  INITIAL_ACCESS: "初始访问",
  COMMAND_AND_CONTROL: "命令与控制",
  EXFILTRATION: "数据外泄",
  IMPACT: "破坏性影响",
  RECONNAISSANCE: "侦察",
  DEFENSE_EVASION: "防御规避",
  COLLECTION: "数据收集",
  DISCOVERY: "信息探测",
};

export function threatZh(value?: string | null): string {
  if (!value) return "—";
  return THREAT_ZH[value] ?? String(value);
}

// Source/action common values from the agent-brain mock events.
export const SOURCE_TYPE_ZH: Record<string, string> = {
  EDR: "终端检测",
  WAF: "Web 应用防火墙",
  NDR: "网络检测",
  IDS: "入侵检测",
  SIEM: "安全运营平台",
  SAST: "静态扫描",
  CLOUD: "云审计",
};

export function sourceTypeZh(value?: string | null): string {
  if (!value) return "—";
  return SOURCE_TYPE_ZH[String(value).toUpperCase()] ?? String(value);
}
