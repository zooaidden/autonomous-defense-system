// Chinese localization for status enums used by the actuator-service execution
// record, the OPS executor envelope, the audit trail steps, and frontend task
// lifecycle states. Always upper-cases the input before lookup.

export const STATUS_ZH: Record<string, string> = {
  // actuator / executor
  SUCCEEDED: "执行成功",
  SUCCESS: "成功",
  FAILED: "执行失败",
  FAILURE: "失败",
  SKIPPED: "已跳过",
  PENDING_APPROVAL: "等待人工审批",
  REQUIRES_APPROVAL: "需人工审批",
  BLOCKED: "已被阻断",
  REJECTED: "已拒绝",
  EXECUTED: "已执行",
  INVALID_INPUT: "输入异常",
  TIMEOUT: "执行超时",
  RUNTIME_ERROR: "运行时错误",
  AVAILABLE: "可用",
  UNAVAILABLE: "不可用",
  // frontend task lifecycle
  RUNNING: "运行中",
  PENDING: "排队中",
  CANCELED: "已取消",
  CANCELLED: "已取消",
  ERROR: "出错",
  // audit pipeline steps
  STARTED: "已开始",
  COMPLETED: "已完成",
  WARNING: "提示",
};

export function statusZh(value?: string | null): string {
  if (!value) return "—";
  const up = String(value).toUpperCase();
  return STATUS_ZH[up] ?? String(value);
}

// Specific localization for the OPS audit trail step ids.
export const OPS_AUDIT_STEP_ZH: Record<string, string> = {
  received_instruction: "接收指令",
  parsed_intent: "意图解析",
  dangerous_intent_detected: "识别为高危指令",
  mcp_context_collected: "采集 MCP 上下文",
  safety_validated: "安全闸门校验",
  safety_validation_blocked: "安全闸门拦截",
  executed_or_blocked: "执行 / 阻断",
  execution_skipped: "跳过执行",
  final_answer_generated: "生成最终回答",
};

export function opsAuditStepZh(value?: string | null): string {
  if (!value) return "—";
  return OPS_AUDIT_STEP_ZH[value] ?? String(value);
}
