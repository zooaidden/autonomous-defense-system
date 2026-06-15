// Bridge module: keeps the TaskStore and the EventStore in sync. When a task
// associated with a SecurityEvent transitions, we update the matching
// disposition chip. Installed once at app bootstrap.

import { useTaskStore } from "./taskStore";
import { useEventStore } from "./eventStore";
import type { DispositionStatus } from "../utils/humanReadable/describeSecurityEvent";
import type { Task } from "./taskTypes";

function deriveDisposition(task: Task): DispositionStatus {
  if (task.status === "running" || task.status === "pending") return "processing";
  if (task.status === "error") return "failed";
  if (task.status === "canceled") return "untouched";
  // success path — inspect the workflow / ops payload to choose a finer chip.
  const wf = task.result?.workflow;
  if (wf) {
    const actuator = wf.actuatorResponse?.status?.toUpperCase();
    if (actuator === "SUCCEEDED") return "resolved";
    if (actuator === "FAILED") return "failed";
    if (actuator === "SKIPPED") return "needs-approval";
    return "resolved";
  }
  const ops = task.result?.ops;
  if (ops) {
    const decision = ops.safetyValidation?.decision;
    if (decision === "BLOCK") return "blocked";
    if (decision === "REQUIRE_APPROVAL") return "needs-approval";
    return "resolved";
  }
  return "resolved";
}

let installed = false;

export function installTaskEventBridge(): void {
  if (installed) return;
  installed = true;

  useTaskStore.subscribe((state, prev) => {
    const eventStore = useEventStore.getState();
    for (const id of state.order) {
      const task = state.tasks[id];
      const prevTask = prev.tasks[id];
      if (!task) continue;
      const eventId = task.derivedEventId ?? task.request.event?.eventId;
      if (!eventId) continue;
      // Only emit on actual change (avoid render thrash).
      const changed =
        !prevTask ||
        prevTask.status !== task.status ||
        prevTask.activePhase !== task.activePhase;
      if (!changed) continue;
      const status = deriveDisposition(task);
      eventStore.setDisposition(eventId, {
        status,
        taskId: task.id,
        updatedAt: new Date().toISOString(),
        reason: task.error,
      });
    }
  });
}
