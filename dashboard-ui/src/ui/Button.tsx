// Unified button atom. Replaces ad-hoc btn-* classes scattered across the
// app. Variants:
//   primary   — main call to action (gradient + glow)
//   secondary — neutral panel action (outline)
//   ghost     — minimal in-row trigger (text only)
//   danger    — destructive / blocking actions (only used for explicit blocks)

import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  leadingIcon?: ReactNode;
  trailingIcon?: ReactNode;
  fullWidth?: boolean;
}

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  leadingIcon,
  trailingIcon,
  fullWidth,
  className,
  disabled,
  children,
  ...rest
}: ButtonProps) {
  const classes = [
    "ui-btn",
    `ui-btn-${variant}`,
    `ui-btn-${size}`,
    fullWidth ? "ui-btn-fullwidth" : "",
    loading ? "ui-btn-loading" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button {...rest} disabled={disabled || loading} className={classes}>
      {loading ? (
        <span className="ui-btn-spinner" aria-hidden />
      ) : leadingIcon ? (
        <span className="ui-btn-icon" aria-hidden>
          {leadingIcon}
        </span>
      ) : null}
      <span className="ui-btn-label">{children}</span>
      {!loading && trailingIcon ? (
        <span className="ui-btn-icon" aria-hidden>
          {trailingIcon}
        </span>
      ) : null}
    </button>
  );
}
