// Surface atom: a single .panel-style container with a structured header.
// Pages can keep using the legacy `.panel` class for compatibility, but new
// code should consume this component so we have one place to evolve spacing
// and glow.

import type { ReactNode } from "react";

interface PanelProps {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  // Optional left rail (e.g. a status dot).
  rail?: ReactNode;
  tone?: "neutral" | "info" | "ok" | "warn" | "danger";
  // Disable inner padding (e.g. when embedding a custom layout).
  flush?: boolean;
  className?: string;
  children: ReactNode;
}

export function Panel({
  title,
  subtitle,
  actions,
  rail,
  tone = "neutral",
  flush = false,
  className,
  children,
}: PanelProps) {
  const classes = [
    "ui-panel",
    `ui-panel-${tone}`,
    flush ? "ui-panel-flush" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <section className={classes}>
      {(title || subtitle || actions || rail) && (
        <header className="ui-panel-head">
          {rail ? <div className="ui-panel-rail">{rail}</div> : null}
          <div className="ui-panel-headtext">
            {title ? <h3 className="ui-panel-title">{title}</h3> : null}
            {subtitle ? <p className="ui-panel-subtitle">{subtitle}</p> : null}
          </div>
          {actions ? <div className="ui-panel-actions">{actions}</div> : null}
        </header>
      )}
      <div className="ui-panel-body">{children}</div>
    </section>
  );
}
