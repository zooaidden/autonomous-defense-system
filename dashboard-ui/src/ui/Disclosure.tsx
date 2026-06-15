// Disclosure atom: a click-to-expand row used by the strategy execution
// table rewrite and the audit raw-data drawers. Internal <details>/<summary>
// gives keyboard accessibility for free, while custom styling makes the
// caret + active border match our dark theme.

import { useId, type ReactNode } from "react";

interface DisclosureProps {
  summary: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
  tone?: "neutral" | "info" | "ok" | "warn" | "danger";
  className?: string;
}

export function Disclosure({
  summary,
  children,
  defaultOpen = false,
  tone = "neutral",
  className,
}: DisclosureProps) {
  const id = useId();
  return (
    <details
      className={`ui-disclosure ui-disclosure-${tone} ${className ?? ""}`}
      open={defaultOpen}
    >
      <summary className="ui-disclosure-summary" aria-controls={id}>
        <span className="ui-disclosure-caret" aria-hidden>
          ▸
        </span>
        <span className="ui-disclosure-summary-inner">{summary}</span>
      </summary>
      <div id={id} className="ui-disclosure-body">
        {children}
      </div>
    </details>
  );
}
