import { useMemo, useState } from "react";
import { OPS_EXAMPLES, type OpsExampleCategory } from "../../mock/opsMockData";

// Top input panel: textarea + example chip groups + Run button.

interface OpsRunnerProps {
  loading: boolean;
  onRun: (instruction: string) => void;
  initialInstruction?: string;
}

// Category metadata. Order here drives the display order of chip groups
// so the "safe -> approval -> dangerous -> injection -> config" arc
// reads naturally from left to right.
const CATEGORY_META: Record<
  OpsExampleCategory,
  { label: string; tone: "safe" | "warn" | "danger" }
> = {
  readonly: { label: "只读查询", tone: "safe" },
  approval: { label: "需要审批", tone: "warn" },
  dangerous: { label: "高危命令", tone: "danger" },
  injection: { label: "提示注入", tone: "danger" },
  config: { label: "配置篡改", tone: "danger" },
};

const CATEGORY_ORDER: OpsExampleCategory[] = [
  "readonly",
  "approval",
  "dangerous",
  "injection",
  "config",
];

export function OpsRunner({ loading, onRun, initialInstruction = "" }: OpsRunnerProps) {
  const [text, setText] = useState(initialInstruction);

  const trimmed = text.trim();
  const canRun = trimmed.length > 0 && !loading;

  const grouped = useMemo(() => {
    const map: Record<OpsExampleCategory, typeof OPS_EXAMPLES> = {
      readonly: [],
      approval: [],
      dangerous: [],
      injection: [],
      config: [],
    };
    for (const ex of OPS_EXAMPLES) {
      map[ex.category].push(ex);
    }
    return map;
  }, []);

  const handleSubmit = () => {
    if (!canRun) return;
    onRun(trimmed);
  };

  const handleExample = (instruction: string, autoRun: boolean) => {
    setText(instruction);
    if (autoRun && !loading) onRun(instruction);
  };

  return (
    <section className="ops-runner panel-glow">
      <header className="ops-runner-head">
        <div>
          <h2 className="ops-runner-title">自然语言运维指令</h2>
          <p className="ops-runner-sub">
            描述你想了解的系统状况或想执行的运维操作，Agent 会依次跑「反提示注入护栏 → 配置确定性护栏 →
            意图安全校验 → MCP 状态采集 → 最小权限执行」，并把整条审计链路展示出来。
          </p>
        </div>
        <span className="ops-runner-target">提交后调用 agent-brain · /ops/chat</span>
      </header>

      <textarea
        className="ops-runner-input"
        value={text}
        placeholder="例如：查看 8080 端口被哪个进程占用，并判断是否存在异常外联"
        rows={3}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          // Cmd/Ctrl + Enter to submit, just like a chat box.
          if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
            e.preventDefault();
            handleSubmit();
          }
        }}
        disabled={loading}
      />

      <div className="ops-runner-example-groups">
        {CATEGORY_ORDER.map((cat) => {
          const items = grouped[cat];
          if (!items || items.length === 0) return null;
          const meta = CATEGORY_META[cat];
          return (
            <div key={cat} className={`ops-example-group tone-${meta.tone}`}>
              <span className="ops-example-group-label">{meta.label}</span>
              <div className="ops-example-group-chips">
                {items.map((ex) => (
                  <button
                    key={ex.id}
                    type="button"
                    className={`ops-example-chip tone-${meta.tone}`}
                    onClick={() => handleExample(ex.instruction, false)}
                    disabled={loading}
                    title={ex.hint ?? ex.label}
                  >
                    <span className="ops-example-chip-label">{ex.label}</span>
                    {ex.hint ? (
                      <span className="ops-example-chip-hint">{ex.hint}</span>
                    ) : null}
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>

      <div className="ops-runner-footer">
        <span className="muted ops-runner-hint">
          小贴士：⌘/Ctrl + Enter 直接运行；危险命令、注入提示与配置写入均会被多层护栏拦截，绝不会真正执行。
        </span>
        <button
          type="button"
          className="ops-run-btn"
          onClick={handleSubmit}
          disabled={!canRun}
        >
          {loading ? (
            <>
              <span className="ops-run-btn-spinner" aria-hidden />
              运行中…
            </>
          ) : (
            <>▶ 运行</>
          )}
        </button>
      </div>
    </section>
  );
}
