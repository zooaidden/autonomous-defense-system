// Convert a Red-Teamer Challenge into a one-line Chinese sentence.

import type { Challenge } from "../../types";
import { severityZh } from "./zh/risk";

export function describeChallengeHuman(c: Challenge): string {
  return `「${c.title}」(${severityZh(c.severity)})：${c.description}`;
}
