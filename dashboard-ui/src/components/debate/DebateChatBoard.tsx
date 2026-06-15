// Debate timeline rendered as WeChat-style chat bubbles. Each turn supports
// Markdown content, a streaming typewriter intro for the active turn, and a
// "show full" disclosure for long messages so the timeline stays scannable.

import { useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import { motion } from "framer-motion";
import type { DebateTurn } from "../../types";

const ACTOR_META: Record<
  string,
  { label: string; side: "left" | "right"; hue: string; initials: string }
> = {
  Planner: { label: "规划智能体 Planner", side: "left", hue: "bubble-planner", initials: "P" },
  "Red-Teamer": { label: "红队 Red-Teamer", side: "left", hue: "bubble-red", initials: "R" },
  "Planner-Revision": {
    label: "修订智能体 Planner-Revision",
    side: "left",
    hue: "bubble-revision",
    initials: "PR",
  },
  Coordinator: {
    label: "协调智能体 Coordinator",
    side: "right",
    hue: "bubble-coordinator",
    initials: "C",
  },
};

const TYPEWRITER_CHARS_PER_TICK = 8;
const TYPEWRITER_INTERVAL_MS = 32;
const FOLD_AFTER_CHARS = 280;

interface DebateChatBoardProps {
  turns: DebateTurn[];
  activeStep?: number;
}

function humanizeActor(actor: string): string {
  return ACTOR_META[actor]?.label ?? actor;
}

// Attempt to extract a JSON object out of a Coordinator message so we can
// hide raw fields like "Decision=" prefix. If the body isn't JSON we just
// pass it through.
function cleanMessage(actor: string, raw: string): string {
  if (actor !== "Coordinator") return raw;
  return raw.replace(/^Decision=/i, "").trim();
}

export function DebateChatBoard({ turns, activeStep = -1 }: DebateChatBoardProps) {
  const rows = useMemo(() => {
    return turns.map((t, idx) => {
      const meta = ACTOR_META[t.actor] ?? {
        label: t.actor,
        side: "left" as const,
        hue: "bubble-default",
        initials: t.actor.slice(0, 2),
      };
      const text = cleanMessage(t.actor, t.message);
      const timeShort =
        t.timestamp && t.timestamp.length > 16
          ? t.timestamp.slice(0, 16).replace("T", " ")
          : (t.timestamp ?? "");
      return {
        idx,
        actor: t.actor,
        meta,
        text,
        timeShort,
        isActive: activeStep >= 0 && idx === activeStep,
      };
    });
  }, [turns, activeStep]);

  if (!rows.length) {
    return (
      <div className="debate-chat-empty">
        <p className="muted">
          暂无博弈回合记录。完成一次任务（防御编排或运维 Agent）后将在此以聊天形式回放。
        </p>
      </div>
    );
  }

  return (
    <div className="debate-chat-board">
      {rows.map((row) => (
        <motion.div
          key={`${row.actor}-${row.idx}-${row.timeShort}`}
          className={`debate-chat-row ${row.meta.side === "right" ? "is-self" : "is-peer"} ${
            row.isActive ? "is-active-turn" : ""
          }`}
          layout
          initial={{ opacity: 0, y: 12, scale: 0.96 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.32, ease: "easeOut" }}
        >
          <div className={`debate-avatar ${row.meta.hue}`} title={humanizeActor(row.actor)}>
            {row.meta.initials}
          </div>
          <div className="debate-chat-main">
            <div className="debate-chat-meta">
              <span className="debate-chat-name">{humanizeActor(row.actor)}</span>
              {row.timeShort ? <span className="muted">{row.timeShort}</span> : null}
            </div>
            <div className={`debate-bubble ${row.meta.hue}`}>
              <BubbleBody text={row.text} isActive={row.isActive} side={row.meta.side} />
            </div>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

interface BubbleBodyProps {
  text: string;
  isActive: boolean;
  side: "left" | "right";
}

function BubbleBody({ text, isActive }: BubbleBodyProps) {
  const folded = text.length > FOLD_AFTER_CHARS;
  const [expanded, setExpanded] = useState(false);
  const displayText = folded && !expanded ? `${text.slice(0, FOLD_AFTER_CHARS).trimEnd()}…` : text;
  const animated = useTypewriter(displayText, isActive);

  return (
    <>
      <div className="debate-bubble-text">
        <ReactMarkdown
          // Keep paragraph spacing tight; restrict GFM extensions that we
          // don't currently style (tables of arbitrary width, raw HTML, etc.).
          components={{
            // Drop heading levels into bold + spacing so they don't fight the
            // bubble's compact look.
            h1: ({ children }) => <strong className="debate-md-h">{children}</strong>,
            h2: ({ children }) => <strong className="debate-md-h">{children}</strong>,
            h3: ({ children }) => <strong className="debate-md-h">{children}</strong>,
            code: ({ children }) => <code className="debate-md-code">{children}</code>,
            pre: ({ children }) => <pre className="debate-md-pre">{children}</pre>,
            a: ({ children }) => <span className="debate-md-link">{children}</span>,
          }}
        >
          {animated}
        </ReactMarkdown>
        {isActive && animated.length < displayText.length ? (
          <span className="debate-bubble-cursor" aria-hidden />
        ) : null}
      </div>
      {folded ? (
        <button
          type="button"
          className="debate-bubble-toggle"
          onClick={() => setExpanded((v) => !v)}
        >
          {expanded ? "收起" : "展开全部"}
        </button>
      ) : null}
    </>
  );
}

// Typewriter effect — reveals characters in chunks so even long messages
// finish in well under a second. Disabled when the row isn't the active step.
function useTypewriter(text: string, enabled: boolean): string {
  const [cursor, setCursor] = useState(enabled ? 0 : text.length);

  useEffect(() => {
    if (!enabled) {
      setCursor(text.length);
      return;
    }
    setCursor(0);
    const id = window.setInterval(() => {
      setCursor((c) => {
        const next = c + TYPEWRITER_CHARS_PER_TICK;
        if (next >= text.length) {
          window.clearInterval(id);
          return text.length;
        }
        return next;
      });
    }, TYPEWRITER_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, [text, enabled]);

  return text.slice(0, cursor);
}
