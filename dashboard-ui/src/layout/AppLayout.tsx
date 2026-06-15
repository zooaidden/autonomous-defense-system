import { Link, NavLink } from "react-router-dom";
import { useEffect, useState, type PropsWithChildren } from "react";
import { AGENT_BRAIN_BASE_URL } from "../api/config";
import { TaskTrayFAB } from "../components/TaskTrayFAB";
import { ToastViewport } from "../ui/Toast";
import type { SystemStatusResponse } from "../types/systemStatus";
import "../styles/task-tray.css";
import "../styles/agent-relay.css";

// Top navigation. Each menu item carries a glyph (emoji) so users can tell
// the pages apart at a glance even without reading the Chinese label.
const menus: Array<{ to: string; label: string; icon: string; sub: string }> = [
  { to: "/", label: "防御态势", icon: "◎", sub: "Dashboard" },
  { to: "/events", label: "事件中心", icon: "✦", sub: "Events" },
  { to: "/debate", label: "智能体协作", icon: "✺", sub: "Debate" },
  { to: "/executions", label: "策略执行", icon: "▶", sub: "Strategy exec" },
  { to: "/ops", label: "智能运维", icon: "✶", sub: "OS Ops" },
  { to: "/system", label: "系统状态", icon: "⚙", sub: "Status" },
  { to: "/tasks", label: "任务中心", icon: "⚡", sub: "Tasks" },
];

function usePlatformFooter() {
  // Best-effort fetch of the platform footer line. We deliberately do
  // not block render and silently fall back to a generic message when
  // agent-brain is unreachable so the layout always paints.
  const [footer, setFooter] = useState<string>(
    "A2 · 麒麟操作系统安全智能运维 Agent · 多 MCP / 安全闸门 / 最小权限执行",
  );
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch(`${AGENT_BRAIN_BASE_URL}/system/status`);
        if (!res.ok) return;
        const json = (await res.json()) as SystemStatusResponse;
        if (cancelled) return;
        const platform = json.platform;
        const tags = [
          platform.osPretty || platform.system,
          platform.machine,
          platform.kylinVersion ? "Kylin V11" : null,
        ].filter(Boolean);
        if (tags.length) {
          setFooter(
            `A2 · 麒麟操作系统安全智能运维 Agent · 平台 ${tags.join(" · ")} · 多 MCP / 多层护栏 / 最小权限`,
          );
        }
      } catch {
        // Swallow: footer stays on the default text.
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);
  return footer;
}

export function AppLayout({ children }: PropsWithChildren) {
  const footer = usePlatformFooter();
  return (
    <div className="app-shell">
      <div className="aurora" aria-hidden>
        <span className="aurora-blob a1" />
        <span className="aurora-blob a2" />
        <span className="aurora-blob a3" />
      </div>
      <header className="topbar">
        <Link to="/" className="brand">
          <span className="brand-mark">⛨</span>
          <span className="brand-name">
            <span className="brand-name-zh">自治防御系统</span>
            <span className="brand-name-en">Autonomous Defense Suite</span>
          </span>
        </Link>
        <nav className="menu" aria-label="主导航">
          {menus.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => (isActive ? "menu-item active" : "menu-item")}
              title={item.label}
            >
              <span className="menu-icon" aria-hidden>{item.icon}</span>
              <span className="menu-label">{item.label}</span>
            </NavLink>
          ))}
        </nav>
      </header>
      <main className="content">{children}</main>
      <footer className="appfoot">
        <span className="muted">{footer}</span>
      </footer>
      <TaskTrayFAB />
      <ToastViewport />
    </div>
  );
}
