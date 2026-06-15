// Side-sheet atom: slides in from the right. Used by the FAB drawer and the
// developer-tools "view raw audit" launcher.

import { useEffect, type ReactNode } from "react";

interface SheetProps {
  open: boolean;
  onClose: () => void;
  title?: ReactNode;
  width?: number;
  side?: "left" | "right";
  children: ReactNode;
}

export function Sheet({ open, onClose, title, width = 420, side = "right", children }: SheetProps) {
  // Close on Esc when open.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  // Lock body scroll while open.
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  if (!open) return null;
  return (
    <div className={`ui-sheet-root ui-sheet-${side}`}>
      <div className="ui-sheet-scrim" onClick={onClose} aria-hidden />
      <aside
        className="ui-sheet-panel"
        style={{ width }}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === "string" ? title : undefined}
      >
        <header className="ui-sheet-head">
          <h3 className="ui-sheet-title">{title}</h3>
          <button
            type="button"
            className="ui-sheet-close"
            onClick={onClose}
            aria-label="关闭面板"
          >
            ✕
          </button>
        </header>
        <div className="ui-sheet-body">{children}</div>
      </aside>
    </div>
  );
}
