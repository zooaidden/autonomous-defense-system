import type { ActuatorWorkflowResponse } from "../types/workflow";
import { ActuatorWorkflowSummaryPanel } from "./ActuatorArtifactsPanel";

interface ActuatorOutcomePanelProps {
  response: ActuatorWorkflowResponse | null;
}

export function ActuatorOutcomePanel({ response }: ActuatorOutcomePanelProps) {
  if (!response || Object.keys(response).length === 0) {
    return (
      <div className="panel">
        <h3>Actuator</h3>
        <p className="muted">No actuator response in this bundle.</p>
      </div>
    );
  }

  return <ActuatorWorkflowSummaryPanel response={response} />;
}
