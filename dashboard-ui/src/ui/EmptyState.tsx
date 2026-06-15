// EmptyState atom: a centered icon + title + description + optional CTA.

import type { ReactNode } from "react";

interface EmptyStateProps {
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}

export function EmptyState({ icon, title, description, actions, className }: EmptyStateProps) {
  return (
    <div className={`ui-empty ${className ?? ""}`}>
      {icon ? <div className="ui-empty-icon" aria-hidden>{icon}</div> : null}
      <h4 className="ui-empty-title">{title}</h4>
      {description ? <p className="ui-empty-desc">{description}</p> : null}
      {actions ? <div className="ui-empty-actions">{actions}</div> : null}
    </div>
  );
}
