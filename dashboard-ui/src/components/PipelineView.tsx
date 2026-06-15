// @deprecated Replaced by AgentRelayProgress. Kept temporarily for any
// downstream tooling/screenshot snapshots. New code should not use this.
interface PipelineViewProps {
  currentStep: "event" | "debate" | "verify" | "execute";
}

const steps: Array<{ key: PipelineViewProps["currentStep"]; label: string }> = [
  { key: "event", label: "事件" },
  { key: "debate", label: "博弈" },
  { key: "verify", label: "验证" },
  { key: "execute", label: "执行" },
];

export function PipelineView({ currentStep }: PipelineViewProps) {
  const currentIndex = steps.findIndex((s) => s.key === currentStep);
  return (
    <div className="pipeline">
      {steps.map((step, idx) => (
        <div key={step.key} className={idx <= currentIndex ? "pipeline-step active" : "pipeline-step"}>
          <span>{step.label}</span>
        </div>
      ))}
    </div>
  );
}

