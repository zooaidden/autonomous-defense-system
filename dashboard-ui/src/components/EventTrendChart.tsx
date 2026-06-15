import type { SecurityEvent } from "../types";

interface EventTrendChartProps {
  events: SecurityEvent[];
  // 显示最近 N 天，默认 7 天
  windowDays?: number;
  title?: string;
}

interface DayBucket {
  date: string;
  total: number;
  highRisk: number;
}

// 把事件按日期聚合，返回最近 ``windowDays`` 天的桶（缺失日期补 0）
function bucketEventsByDay(events: SecurityEvent[], windowDays: number): DayBucket[] {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const buckets: DayBucket[] = [];
  const dateKey = (d: Date) => d.toISOString().slice(0, 10);

  // 用 Map 聚合
  const byDate = new Map<string, DayBucket>();
  for (const e of events) {
    const ts = new Date(e.timestamp);
    if (Number.isNaN(ts.getTime())) continue;
    const key = dateKey(ts);
    const cur = byDate.get(key) ?? { date: key, total: 0, highRisk: 0 };
    cur.total += 1;
    if (e.riskScore >= 0.8) cur.highRisk += 1;
    byDate.set(key, cur);
  }

  // 倒序回填最近 N 天，保证连续
  for (let i = windowDays - 1; i >= 0; i -= 1) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    const key = dateKey(d);
    buckets.push(byDate.get(key) ?? { date: key, total: 0, highRisk: 0 });
  }
  return buckets;
}

// 把 Y 值线性映射到 SVG 内的像素 y 坐标（值越大 y 越小）
function scaleY(value: number, max: number, height: number, padding: number): number {
  if (max <= 0) return height - padding;
  const usable = height - padding * 2;
  return padding + usable - (value / max) * usable;
}

function buildPath(values: number[], max: number, width: number, height: number, padding: number): string {
  if (values.length === 0) return "";
  const stepX = (width - padding * 2) / Math.max(1, values.length - 1);
  return values
    .map((v, i) => {
      const x = padding + i * stepX;
      const y = scaleY(v, max, height, padding);
      return `${i === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
}

const WIDTH = 560;
const HEIGHT = 160;
const PADDING = 18;

export function EventTrendChart({
  events,
  windowDays = 7,
  title = "近 7 日事件趋势",
}: EventTrendChartProps) {
  const buckets = bucketEventsByDay(events, windowDays);
  const totals = buckets.map((b) => b.total);
  const highRisk = buckets.map((b) => b.highRisk);
  const max = Math.max(1, ...totals);

  const totalPath = buildPath(totals, max, WIDTH, HEIGHT, PADDING);
  const highPath = buildPath(highRisk, max, WIDTH, HEIGHT, PADDING);
  const stepX = (WIDTH - PADDING * 2) / Math.max(1, buckets.length - 1);

  return (
    <div className="panel trend-panel">
      <div className="trend-header">
        <h3>{title}</h3>
        <div className="trend-legend">
          <span className="trend-legend-item">
            <span className="trend-swatch trend-total" /> 全部事件
          </span>
          <span className="trend-legend-item">
            <span className="trend-swatch trend-high" /> 高风险 (≥ 0.8)
          </span>
        </div>
      </div>

      <svg
        className="trend-svg"
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={title}
      >
        {/* baseline grid: 4 条横线 */}
        {[0, 1, 2, 3].map((i) => {
          const y = PADDING + ((HEIGHT - PADDING * 2) / 3) * i;
          return (
            <line
              key={i}
              x1={PADDING}
              y1={y}
              x2={WIDTH - PADDING}
              y2={y}
              stroke="#1d2a4a"
              strokeWidth={1}
            />
          );
        })}

        {/* 全部事件曲线 + 区域 */}
        <path
          d={`${totalPath} L${(WIDTH - PADDING).toFixed(2)},${HEIGHT - PADDING} L${PADDING},${HEIGHT - PADDING} Z`}
          fill="rgba(34, 211, 238, 0.12)"
          stroke="none"
        />
        <path d={totalPath} fill="none" stroke="#22d3ee" strokeWidth={2} />

        {/* 高风险曲线 */}
        <path d={highPath} fill="none" stroke="#fda4af" strokeWidth={2} strokeDasharray="4 3" />

        {/* 数据点 + 数值标签 */}
        {buckets.map((b, i) => {
          const cx = PADDING + i * stepX;
          const cy = scaleY(b.total, max, HEIGHT, PADDING);
          return (
            <g key={b.date}>
              <circle cx={cx} cy={cy} r={3} fill="#22d3ee" />
              {b.total > 0 && (
                <text
                  x={cx}
                  y={cy - 6}
                  fontSize={10}
                  textAnchor="middle"
                  fill="#bfdbfe"
                >
                  {b.total}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      <div className="trend-axis">
        {buckets.map((b) => (
          <span key={b.date} className="trend-axis-label">
            {b.date.slice(5)}
          </span>
        ))}
      </div>
    </div>
  );
}
