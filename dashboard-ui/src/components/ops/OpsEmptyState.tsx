interface OpsEmptyStateProps {
  useMock: boolean;
}

// Friendly placeholder shown before the user runs anything.
export function OpsEmptyState({ useMock }: OpsEmptyStateProps) {
  return (
    <section className="panel-glow ops-empty-card">
      <div className="ops-empty-illust" aria-hidden>
        <span className="ops-empty-orb" />
        <span className="ops-empty-orb delay-1" />
        <span className="ops-empty-orb delay-2" />
      </div>
      <h3 className="ops-empty-title">还没有运行运维指令</h3>
      <p className="ops-empty-desc">
        在上方输入框写下自然语言指令，或直接点示例按钮快速体验。Agent
        会沿着 <strong>接收 → 解析 → MCP 采集 → 安全闸门 → 最小权限执行 → 汇总作答</strong> 六个阶段处理你的请求，并把每一步可视化在下方。
      </p>
      <ul className="ops-empty-tips">
        <li>
          <span className="ops-tip-tag tone-ok">绿色</span>表示安全闸门判定 ALLOW。
        </li>
        <li>
          <span className="ops-tip-tag tone-warn">黄色</span>表示需要人工审批，命令不会执行。
        </li>
        <li>
          <span className="ops-tip-tag tone-danger">红色</span>表示命令被立即阻断，仅展示原因与替代方案。
        </li>
        {useMock ? (
          <li className="muted">
            当前 <code>VITE_USE_MOCK=true</code>：未配置后端时也能展示完整的 UI。
          </li>
        ) : (
          <li className="muted">
            实时模式下会请求 <code>POST /ops/chat</code>，请确认 agent-brain 已运行。
          </li>
        )}
      </ul>
    </section>
  );
}
