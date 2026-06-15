// Convert a single actuator-generated artifact into a human-readable card
// descriptor: a one-line title, an optional badge stack, and either a short
// summary or the structured body to render. Keeps raw JSON out of the UI by
// default; callers can still opt-in via the `rawJson` field.

import { actionZh } from "./zh/action";

export type ArtifactRenderKind =
  | "alert-only"
  | "yaml-policy"
  | "json-object"
  | "structured"
  | "unknown";

export interface ArtifactDescriptor {
  kind: ArtifactRenderKind;
  title: string;
  subtitle?: string;
  // Adapter / format chips rendered in the header.
  badges: Array<{ label: string; tone?: "neutral" | "ok" | "warn" | "danger" }>;
  // For yaml-policy: the raw YAML body (terminal output equivalent — kept as text).
  yamlBody?: string;
  // For json-object: a flat list of "label → value" rows to render as <dl>.
  rows: Array<{ label: string; value: string }>;
  // Always-available raw form so a developer-tools sheet can offer "download".
  rawJson: string;
}

function pickString(record: Record<string, unknown>, key: string): string {
  const v = record[key];
  return v == null ? "" : String(v);
}

function flattenRows(value: unknown, prefix = ""): Array<{ label: string; value: string }> {
  if (value == null) return [];
  if (typeof value !== "object" || Array.isArray(value)) {
    return [{ label: prefix || "value", value: String(value) }];
  }
  const out: Array<{ label: string; value: string }> = [];
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const label = prefix ? `${prefix}.${k}` : k;
    if (v != null && typeof v === "object" && !Array.isArray(v)) {
      out.push(...flattenRows(v, label));
    } else if (Array.isArray(v)) {
      out.push({ label, value: v.map((x) => String(x ?? "")).join(", ") });
    } else {
      out.push({ label, value: String(v ?? "—") });
    }
  }
  return out;
}

export function describeArtifactHuman(artifact: Record<string, unknown>): ArtifactDescriptor {
  const adapter = pickString(artifact, "adapter");
  const kind = pickString(artifact, "kind");
  const format = pickString(artifact, "format");
  const action = pickString(artifact, "action") || pickString(artifact, "type");
  const target = pickString(artifact, "target");

  const rawJson = (() => {
    try {
      return JSON.stringify(artifact, null, 2);
    } catch {
      return String(artifact);
    }
  })();

  const badges: ArtifactDescriptor["badges"] = [];
  if (adapter) badges.push({ label: adapter, tone: "neutral" });
  if (format) badges.push({ label: format.toUpperCase(), tone: "neutral" });

  // ALERT_ONLY card — already business-friendly. Surface message/reason directly.
  if (kind === "ALERT_ONLY") {
    badges.push({ label: "仅告警", tone: "warn" });
    return {
      kind: "alert-only",
      title: `仅告警工件${target ? ` · 目标 ${target}` : ""}`,
      subtitle: pickString(artifact, "message") || "未提供告警说明",
      badges,
      rows: [
        { label: "目标", value: target || "—" },
        { label: "动作", value: pickString(artifact, "effect") || "—" },
        { label: "说明", value: pickString(artifact, "message") || "—" },
        { label: "原因", value: pickString(artifact, "reason") || "—" },
      ],
      rawJson,
    };
  }

  // YAML policy artifact — keep the body as text (YAML is itself the deliverable).
  if (format === "yaml" && typeof artifact.content === "string") {
    return {
      kind: "yaml-policy",
      title: action
        ? `${actionZh(action)}策略${target ? ` · ${target}` : ""}`
        : `网络策略${target ? ` · ${target}` : ""}`,
      subtitle: "下方为可直接下发的策略片段（保留原始 YAML 文本，便于运维核对）。",
      badges,
      yamlBody: artifact.content,
      rows: [],
      rawJson,
    };
  }

  // Structured JSON content — flatten into label/value rows.
  if (format === "json") {
    const content = artifact.content;
    return {
      kind: "json-object",
      title: action
        ? `${actionZh(action)}工件${target ? ` · ${target}` : ""}`
        : `结构化工件${target ? ` · ${target}` : ""}`,
      badges,
      rows: flattenRows(content),
      rawJson,
    };
  }

  // Unknown / structured fallback: surface the top-level keys without raw JSON.
  return {
    kind: "structured",
    title: "执行工件",
    badges,
    rows: flattenRows(artifact).filter(
      (r) => r.label !== "content" && r.label !== "format" && r.label !== "adapter",
    ),
    rawJson,
  };
}
