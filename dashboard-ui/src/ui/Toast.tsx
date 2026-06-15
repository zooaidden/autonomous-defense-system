// Lightweight toast atom + tiny module-level controller. Avoids pulling in a
// dedicated toast library while still letting us notify users from anywhere
// (e.g. when a task fires from a page they've since left).

import { useEffect, useState } from "react";

export type ToastTone = "info" | "ok" | "warn" | "danger";
export interface ToastMessage {
  id: string;
  tone: ToastTone;
  text: string;
  ttlMs?: number;
}

type Listener = (toasts: ToastMessage[]) => void;

class ToastBus {
  private items: ToastMessage[] = [];
  private listeners = new Set<Listener>();

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    listener(this.items);
    return () => this.listeners.delete(listener);
  }

  emit(toast: Omit<ToastMessage, "id"> & { id?: string }): string {
    const id = toast.id ?? `t-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    const next: ToastMessage = { ttlMs: 4200, ...toast, id };
    this.items = [next, ...this.items].slice(0, 6);
    this.notify();
    if (next.ttlMs && next.ttlMs > 0) {
      setTimeout(() => this.dismiss(id), next.ttlMs);
    }
    return id;
  }

  dismiss(id: string) {
    this.items = this.items.filter((t) => t.id !== id);
    this.notify();
  }

  private notify() {
    this.listeners.forEach((l) => l(this.items.slice()));
  }
}

export const toastBus = new ToastBus();

export function notify(text: string, tone: ToastTone = "info", ttlMs?: number) {
  return toastBus.emit({ text, tone, ttlMs });
}

// Component to mount once at the layout root.
export function ToastViewport() {
  const [items, setItems] = useState<ToastMessage[]>([]);
  useEffect(() => toastBus.subscribe(setItems), []);
  if (!items.length) return null;
  return (
    <div className="ui-toast-viewport" role="status" aria-live="polite">
      {items.map((t) => (
        <div key={t.id} className={`ui-toast ui-toast-${t.tone}`}>
          <span className="ui-toast-text">{t.text}</span>
          <button
            type="button"
            className="ui-toast-close"
            onClick={() => toastBus.dismiss(t.id)}
            aria-label="关闭提示"
          >
            ✕
          </button>
        </div>
      ))}
    </div>
  );
}
