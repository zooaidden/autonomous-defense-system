// actuator-service workflow response → short Chinese sentences for the UI.

import type { ActuatorWorkflowResponse } from "../../types/workflow";

export function describeActuatorHuman(response: ActuatorWorkflowResponse | null): string[] {
  if (!response || Object.keys(response).length === 0) {
    return ["尚无执行器回执（可能尚未触发自动下发）。"];
  }
  const st = String(response.status ?? "").toUpperCase();
  const lines: string[] = [];
  if (st === "SUCCEEDED") {
    lines.push("执行器已成功接收策略并完成一轮下发仿真（含生成的审计与策略工件）。");
  } else if (st === "FAILED") {
    lines.push("执行器返回失败：请优先查看失败原因并核对环境与适配器配置。");
  } else if (st === "SKIPPED") {
    lines.push("本次流程未触发自动执行（策略尚未获批自动下发或被编排层跳过）。");
  } else {
    lines.push(`执行器状态：${response.status ?? "未知"}。`);
  }
  if (response.executionId) {
    lines.push(`执行流水号：${response.executionId}，可与后端审计日志对齐追踪。`);
  }
  if (response.failureReason) {
    lines.push(`失败原因摘要：${response.failureReason}`);
  }
  const rb = response.rollbackStatus;
  if (rb === "AVAILABLE") {
    lines.push("回滚窗口可用：如需撤销本次变更，可按回滚计划在窗口期内触发复原流程。");
  }
  return lines;
}
