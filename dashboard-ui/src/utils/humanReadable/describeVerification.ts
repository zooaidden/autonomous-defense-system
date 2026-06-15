// Verification (formal-verifier) result → 1-3 short Chinese sentences for the UI.

export function describeVerificationHuman(
  verification: Record<string, unknown> | null | undefined,
): string[] {
  if (!verification || typeof verification !== "object") {
    return ["暂无策略校验结论（可能被跳过或未接入校验服务）。"];
  }
  const passed = Boolean((verification as { passed?: boolean }).passed);
  const reason = String((verification as { reason?: unknown }).reason ?? "").trim();
  const violated = (verification as { violatedConstraints?: unknown }).violatedConstraints;
  const warn = (verification as { warnings?: unknown }).warnings;
  const lines: string[] = [];
  if (passed) {
    lines.push("形式化校验已通过：当前策略在已知约束下自洽，可进入执行链评审。");
  } else {
    lines.push("形式化校验未通过：需要收紧策略或补充约束后再执行。");
  }
  if (reason && reason !== "UNKNOWN") {
    lines.push(`校验说明：${reason}`);
  }
  const vcLen = Array.isArray(violated) ? violated.length : 0;
  const wLen = Array.isArray(warn) ? warn.length : 0;
  if (vcLen > 0) lines.push(`违反约束条目：${vcLen} 条（请在详情中逐项处理）。`);
  if (wLen > 0) lines.push(`提示项：${wLen} 条（不影响放行时可作为风险提示留存）。`);
  return lines;
}
