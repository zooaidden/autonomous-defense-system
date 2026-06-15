// KPI tile. When `onClick` (or `href`) is provided the card becomes a real
// button so the hover affordance reflects the actual interaction. Without
// a click handler the card stays as a static <article> — no false promise.

import type { ReactNode } from "react";

type Tone = "neutral" | "ok" | "warn" | "danger" | "info";

interface MetricCardProps {
  title: string;
  value: number | string;
  subtitle: string;
  tone?: Tone;
  onClick?: () => void;
  trailing?: ReactNode;
  hint?: string;
}

export function MetricCard({
  title,
  value,
  subtitle,
  tone = "neutral",
  onClick,
  trailing,
  hint,
}: MetricCardProps) {
  const classes = `metric-card tone-${tone} ${onClick ? "is-clickable" : ""}`;
  const content = (
    <>
      <p className="metric-title">{title}</p>
      <p className="metric-value">{value}</p>
      <p className="metric-subtitle">{subtitle}</p>
      {trailing ? <div className="metric-trailing">{trailing}</div> : null}
    </>
  );
  if (onClick) {
    return (
      <button type="button" className={classes} onClick={onClick} title={hint ?? title}>
        {content}
      </button>
    );
  }
  return (
    <article className={classes} title={hint}>
      {content}
    </article>
  );
}
