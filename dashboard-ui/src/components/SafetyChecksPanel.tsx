import type { SafetyCheck } from "../types";

interface SafetyChecksPanelProps {
  // 6 项独立 safety_check 结果（来自 Coordinator Phase 5 边界判定）
  checks: SafetyCheck[];
  // 是否需要人工审批；任一 safety_check 不通过都会触发 true
  humanApprovalRequired: boolean;
  // 是否允许自动执行；与 humanApprovalRequired 反向
  autoExecutionAllowed: boolean;
  // 命中的 approval_reason 列表（人类可读触发原因）
  approvalReasons?: string[];
  // 顶部标题（默认 "人工审批边界判定"）
  title?: string;
}

const EMPTY_HINT = "Coordinator 还未输出 safety_checks，无法判定审批边界。";

export function SafetyChecksPanel({
  checks,
  humanApprovalRequired,
  autoExecutionAllowed,
  approvalReasons = [],
  title = "人工审批边界判定",
}: SafetyChecksPanelProps) {
  const passedCount = checks.filter((c) => c.passed).length;
  const totalCount = checks.length;
  const requireApproval = humanApprovalRequired || !autoExecutionAllowed;

  return (
    <div className="panel">
      <div className="safety-header">
        <h3>{title}</h3>
        {totalCount > 0 && (
          <span className={requireApproval ? "badge err" : "badge ok"}>
            {requireApproval ? "需人工审批" : "可自动执行"}
          </span>
        )}
      </div>

      {totalCount === 0 ? (
        <p className="mcp-empty">{EMPTY_HINT}</p>
      ) : (
        <>
          <div className="safety-summary">
            <span className="muted">
              通过 {passedCount} / {totalCount} 项
            </span>
            <span className="muted"> · </span>
            <span className="muted">
              是否允许自动执行：{autoExecutionAllowed ? "是" : "否"}
            </span>
          </div>
          <ul className="safety-checks">
            {checks.map((check) => (
              <li
                key={check.id}
                className={check.passed ? "safety-item pass" : "safety-item fail"}
              >
                <div className="safety-item-header">
                  <span className="safety-item-icon">
                    {check.passed ? "✓" : "✗"}
                  </span>
                  <span className="safety-item-label">{check.label}</span>
                  <span className="safety-item-id">{check.id}</span>
                </div>
                {check.detail && (
                  <p className="safety-item-detail">{check.detail}</p>
                )}
              </li>
            ))}
          </ul>
          {requireApproval && approvalReasons.length > 0 && (
            <div className="safety-reasons">
              <h4>触发原因</h4>
              <ul>
                {approvalReasons.map((reason, idx) => (
                  <li key={`${reason}-${idx}`}>{reason}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}
