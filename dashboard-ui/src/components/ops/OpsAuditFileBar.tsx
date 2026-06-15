import { useState } from "react";
import { AGENT_BRAIN_BASE_URL } from "../../api/config";
import { notify } from "../../ui/Toast";

interface OpsAuditFileBarProps {
  requestId?: string;
  auditFile?: string | null;
}

// Sticky audit-file path display + copy / download actions. Lives below
// the OpsResultHeader so demo presenters can show, in one glance, that
// the entire request was already persisted to disk.

function shortenHome(path: string): string {
  // Replace likely home / workspace prefixes with a tilde for readability.
  return path
    .replace(/^[A-Za-z]:\\Users\\[^\\]+\\/, "~/")
    .replace(/^\/Users\/[^/]+\//, "~/")
    .replace(/^\/home\/[^/]+\//, "~/");
}

export function OpsAuditFileBar({ requestId, auditFile }: OpsAuditFileBarProps) {
  const [copied, setCopied] = useState(false);

  if (!auditFile && !requestId) return null;

  const path = auditFile ?? "";
  const display = path ? shortenHome(path) : "（本次请求未落盘，可能因 AUDIT_LOG_DISABLED=true 而禁用）";

  const handleCopy = async () => {
    if (!path) return;
    try {
      await navigator.clipboard.writeText(path);
      setCopied(true);
      notify("已复制审计文件路径", "info");
      setTimeout(() => setCopied(false), 1500);
    } catch {
      notify("复制失败，请手动选中复制", "danger");
    }
  };

  const downloadUrl = requestId
    ? `${AGENT_BRAIN_BASE_URL}/audit/${encodeURIComponent(requestId)}`
    : "";

  return (
    <section className="ops-audit-bar panel-glow">
      <div className="ops-audit-bar-left">
        <span className="ops-audit-bar-eyebrow">推理链路审计 · auditFile</span>
        <code className="ops-audit-bar-path" title={path || display}>
          {display}
        </code>
      </div>
      <div className="ops-audit-bar-actions">
        <button
          type="button"
          className="ops-audit-bar-btn"
          onClick={handleCopy}
          disabled={!path}
        >
          {copied ? "已复制 ✓" : "复制路径"}
        </button>
        {downloadUrl ? (
          <a
            className="ops-audit-bar-btn primary"
            href={downloadUrl}
            target="_blank"
            rel="noreferrer"
            download
          >
            下载 JSON
          </a>
        ) : null}
      </div>
    </section>
  );
}
