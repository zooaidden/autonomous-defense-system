// /events — Subscribes to EventStore so demo events appended by the
// TaskStore (Sandbox demo / Event-detail dispatch) show up immediately. Each
// row also carries a disposition chip driven by the linked task's lifecycle.

import { useEffect } from "react";
import { Link } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import { fetchEvents } from "../api/services";
import { Chip } from "../ui/Chip";
import { EmptyState } from "../ui/EmptyState";
import {
  selectAllEvents,
  useEventStore,
} from "../store/eventStore";
import {
  describeSecurityEventRow,
  dispositionChip,
  type DispositionStatus,
} from "../utils/humanReadable/describeSecurityEvent";

export function EventListPage() {
  // `selectAllEvents` returns a fresh array on every call — wrap with
  // `useShallow` so Zustand v5 sees a stable reference between renders.
  const events = useEventStore(useShallow(selectAllEvents));
  const setInitialEvents = useEventStore((s) => s.setInitialEvents);
  const disposition = useEventStore((s) => s.disposition);

  useEffect(() => {
    void fetchEvents().then(setInitialEvents);
  }, [setInitialEvents]);

  return (
    <section>
      <header className="events-page-head">
        <div>
          <h1>事件中心</h1>
          <p className="muted">
            汇集感知层（EDR / WAF / NDR / SIEM 等）上报的安全事件，含 Sandbox 演示与处置后回写的衍生事件；点击行查看详情或派发处置任务。
          </p>
        </div>
      </header>

      {!events.length ? (
        <EmptyState
          icon="✨"
          title="暂无事件"
          description={
            <>
              在<Link to="/"> 防御态势 </Link>页运行 Sandbox 演示，或开启{" "}
              <code>VITE_USE_MOCK=true</code> 以加载示例事件。
            </>
          }
        />
      ) : (
        <table className="table evt-table">
          <thead>
            <tr>
              <th>事件编号</th>
              <th>时间</th>
              <th>来源</th>
              <th>行为</th>
              <th>严重程度</th>
              <th>风险分</th>
              <th>处置状态</th>
              <th>详情</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => {
              const row = describeSecurityEventRow(event);
              const disp = disposition[event.eventId];
              const status: DispositionStatus = disp?.status ?? "untouched";
              const chip = dispositionChip(status);
              return (
                <tr key={event.id}>
                  <td>
                    <code>{event.eventId}</code>
                  </td>
                  <td>{row.timestampDisplay}</td>
                  <td>{row.sourceText}</td>
                  <td>{row.actionText}</td>
                  <td>
                    <Chip
                      tone={
                        row.severityTone === "danger"
                          ? "danger"
                          : row.severityTone === "warn"
                            ? "warn"
                            : "ok"
                      }
                    >
                      {row.severityText}
                    </Chip>
                  </td>
                  <td>
                    <span className="risk-cell">
                      <span className="risk-bar" aria-hidden>
                        <span
                          className={`risk-bar-fill tone-${row.severityTone}`}
                          style={{ width: `${row.riskBarPct}%` }}
                        />
                      </span>
                      <span>{row.riskScore.toFixed(2)}</span>
                    </span>
                  </td>
                  <td>
                    <Chip tone={chip.tone} leadingDot>
                      {chip.label}
                    </Chip>
                  </td>
                  <td>
                    <Link to={`/events/${event.id}`}>查看 →</Link>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
