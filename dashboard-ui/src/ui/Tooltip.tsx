// CSS-only tooltip atom. Hover/focus reveals the message above the trigger.
// Avoids portals and a popper dependency — perfect for short hints.

import type { ReactNode } from "react";

interface TooltipProps {
  message: ReactNode;
  side?: "top" | "bottom";
  children: ReactNode;
  className?: string;
}

export function Tooltip({ message, side = "top", children, className }: TooltipProps) {
  return (
    <span className={`ui-tooltip ui-tooltip-${side} ${className ?? ""}`}>
      {children}
      <span className="ui-tooltip-body" role="tooltip">
        {message}
      </span>
    </span>
  );
}
