/** Thin wrapper: delegates to ActuatorArtifactsPanel for consistent artifact rules. */
import { ActuatorArtifactsPanel } from "./ActuatorArtifactsPanel";

interface GeneratedArtifactsListProps {
  artifacts: Array<Record<string, unknown>>;
}

export function GeneratedArtifactsList({ artifacts }: GeneratedArtifactsListProps) {
  return <ActuatorArtifactsPanel artifacts={artifacts} />;
}
