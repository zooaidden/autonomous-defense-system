// AgentRelayProgress: the centerpiece of the new "real-time progress" UX.
//
// Replaces the old static PipelineView with a horizontal relay-baton layout:
//   - Each phase is a circular avatar with an emoji glyph.
//   - The currently-running phase pulses + glows; completed phases get a
//     gold-tinted border; future phases stay grey.
//   - Between every two nodes we draw a connector strip that "fills" via a
//     CSS gradient. A small particle slides along it while running.
//   - No percentages, no traditional progress bar.

import { motion } from "framer-motion";
import type { TaskPhase } from "../store/taskTypes";

interface AgentRelayProgressProps {
  phases: TaskPhase[];
  activePhase: number;
  size?: "sm" | "md" | "lg";
  className?: string;
}

function nodeTone(phase: TaskPhase, isActive: boolean): string {
  if (phase.status === "failed") return "agent-relay-node tone-fail";
  if (phase.status === "done") return "agent-relay-node tone-done";
  if (phase.status === "skipped") return "agent-relay-node tone-skip";
  if (isActive || phase.status === "running") return "agent-relay-node tone-active";
  return "agent-relay-node tone-pending";
}

export function AgentRelayProgress({
  phases,
  activePhase,
  size = "md",
  className,
}: AgentRelayProgressProps) {
  if (!phases.length) return null;

  return (
    <div className={`agent-relay agent-relay-${size} ${className ?? ""}`}>
      <div className="agent-relay-track" aria-hidden />
      <ol className="agent-relay-list">
        {phases.map((phase, idx) => {
          const isActive = idx === activePhase;
          const connectorFilled =
            phases[idx + 1]?.status === "done" ||
            phases[idx]?.status === "done" ||
            (idx < activePhase);
          return (
            <li key={phase.key} className="agent-relay-item">
              <motion.div
                className={nodeTone(phase, isActive)}
                initial={false}
                animate={{
                  scale: isActive && phase.status !== "failed" ? [1, 1.08, 1] : 1,
                }}
                transition={{
                  duration: 1.8,
                  repeat: isActive && phase.status === "running" ? Infinity : 0,
                  ease: "easeInOut",
                }}
                title={phase.detail ?? phase.label}
              >
                <span className="agent-relay-node-glyph" aria-hidden>
                  {phase.icon}
                </span>
                {phase.status === "running" ? (
                  <span className="agent-relay-pulse" aria-hidden />
                ) : null}
                {phase.status === "failed" ? (
                  <span className="agent-relay-node-mark mark-fail" aria-hidden>!</span>
                ) : null}
                {phase.status === "done" ? (
                  <span className="agent-relay-node-mark mark-done" aria-hidden>✓</span>
                ) : null}
              </motion.div>
              <div className="agent-relay-label">
                <span className="agent-relay-label-main">{phase.label}</span>
                <span className="agent-relay-label-meta">
                  {phase.status === "running"
                    ? "进行中"
                    : phase.status === "done"
                      ? "完成"
                      : phase.status === "failed"
                        ? "失败"
                        : phase.status === "skipped"
                          ? "已跳过"
                          : "等待中"}
                </span>
              </div>
              {idx < phases.length - 1 ? (
                <div
                  className={`agent-relay-connector ${connectorFilled ? "is-filled" : ""} ${
                    isActive ? "is-active" : ""
                  }`}
                  aria-hidden
                >
                  <span className="agent-relay-particle" />
                </div>
              ) : null}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
