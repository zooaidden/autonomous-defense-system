import type { SecurityEvent } from "../types";

/**
 * Fixed sandbox demo security event for POST /workflow/run (evt-demo-auto-001).
 * Timestamp is generated when the factory runs so each demo reflects wall-clock time.
 */
export function buildSandboxAutoDefenseDemoEvent(): SecurityEvent {
  return {
    id: "evt-demo-auto-001",
    eventId: "evt-demo-auto-001",
    timestamp: new Date().toISOString(),
    sourceType: "WAF",
    subject: "demo-edge-01",
    action: "suspicious_scan",
    object: "/health",
    context: {
      srcIp: "demo-edge-01",
      dstIp: "demo-test-api-01",
      source_ip: "demo-edge-01",
      target_ip: "demo-test-api-01",
      attackType: "scan",
      path: "/health",
    },
    severity: "LOW",
    riskScore: 0.15,
    labels: ["scan", "waf", "sandbox", "cloud-native"],
  };
}
