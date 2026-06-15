// EventStore: single source of truth for the /events list. Seeds itself with
// the mock events at boot, lets TaskStore append derived events when a
// workflow task starts, and tracks each appended event's disposition status so
// the list table can show a "处置中 / 已处置 / 已阻断" chip without polling.

import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import type { SecurityEvent } from "../types";
import type { DispositionStatus } from "../utils/humanReadable/describeSecurityEvent";

export interface EventDisposition {
  status: DispositionStatus;
  taskId?: string;
  updatedAt: string;
  reason?: string;
}

interface EventStoreState {
  // The list rendered by /events. `initial` holds mock/seed rows, `appended`
  // holds derived rows (e.g. Sandbox demo), and `disposition` maps eventId →
  // current chip state. We keep them split so future API hydration only
  // touches `initial`.
  initial: SecurityEvent[];
  appended: SecurityEvent[];
  disposition: Record<string, EventDisposition>;
  hydrated: boolean;

  setInitialEvents: (events: SecurityEvent[]) => void;
  appendDerivedEvent: (event: SecurityEvent, taskId?: string) => void;
  setDisposition: (eventId: string, disposition: EventDisposition) => void;
  removeAppended: (eventId: string) => void;
}

export const useEventStore = create<EventStoreState>()(
  persist(
    (set) => ({
      initial: [],
      appended: [],
      disposition: {},
      hydrated: false,

      setInitialEvents: (events) => {
        set(() => ({ initial: events, hydrated: true }));
      },

      appendDerivedEvent: (event, taskId) => {
        set((s) => {
          // Avoid duplicating an existing appended event (e.g. demo re-run).
          const exists =
            s.appended.some((e) => e.id === event.id || e.eventId === event.eventId) ||
            s.initial.some((e) => e.id === event.id || e.eventId === event.eventId);
          const nextAppended = exists ? s.appended : [event, ...s.appended];
          const nextDisp: Record<string, EventDisposition> = {
            ...s.disposition,
            [event.eventId]: {
              status: "processing",
              taskId,
              updatedAt: new Date().toISOString(),
            },
          };
          return { appended: nextAppended, disposition: nextDisp };
        });
      },

      setDisposition: (eventId, disposition) => {
        set((s) => ({
          disposition: { ...s.disposition, [eventId]: disposition },
        }));
      },

      removeAppended: (eventId) => {
        set((s) => ({
          appended: s.appended.filter((e) => e.eventId !== eventId),
        }));
      },
    }),
    {
      name: "acd.event-store",
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({
        appended: state.appended,
        disposition: state.disposition,
      }),
    },
  ),
);

// Convenience selector — merges initial + appended events with the newest
// appended row on top.
export function selectAllEvents(state: EventStoreState): SecurityEvent[] {
  return [...state.appended, ...state.initial];
}
