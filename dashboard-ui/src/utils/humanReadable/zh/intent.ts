// Chinese localization for OPS intent ids emitted by ops_intent_parser.

export const INTENT_ZH: Record<string, string> = {
  DISK_USAGE: "查看磁盘使用",
  MEMORY_STATUS: "查看内存状态",
  CPU_LOAD: "查看 CPU 负载",
  PROCESS_LIST: "查看进程列表",
  NETWORK_SOCKETS: "查看网络连接",
  PORT_LOOKUP: "查看端口占用",
  SERVICE_STATUS: "查看服务状态",
  RECENT_LOGS: "分析最近系统错误日志",
  RAW_COMMAND: "原始命令",
  DANGEROUS_COMMAND: "高危命令（已识别）",
  UNKNOWN: "未识别意图",
};

export function intentZh(intent?: string | null): string {
  if (!intent) return "—";
  return INTENT_ZH[intent] ?? String(intent);
}
