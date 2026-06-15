// Tone-aware chip / badge atom. Use for status indicators, kpi tags, etc.

import type { ReactNode } from "react";

export type ChipTone = "neutral" | "info" | "ok" | "warn" | "danger";
type ChipSize = "sm" | "md";
type ChipShape = "pill" | "rect";

interface ChipProps {
  tone?: ChipTone;
  size?: ChipSize;
  shape?: ChipShape;
  leadingDot?: boolean;
  outline?: boolean;
  className?: string;
  title?: string;
  children: ReactNode;
}

export function Chip({
  tone = "neutral",
  size = "sm",
  shape = "pill",
  leadingDot = false,
  outline = false,
  className,
  title,
  children,
}: ChipProps) {
  const classes = [
    "ui-chip",
    `ui-chip-${tone}`,
    `ui-chip-${size}`,
    `ui-chip-${shape}`,
    outline ? "ui-chip-outline" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <span className={classes} title={title}>
      {leadingDot ? <span className="ui-chip-dot" aria-hidden /> : null}
      <span className="ui-chip-label">{children}</span>
    </span>
  );
}
