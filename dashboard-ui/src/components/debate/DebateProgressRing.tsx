interface DebateProgressRingProps {
  progress: number;
}

export function DebateProgressRing({ progress }: DebateProgressRingProps) {
  const pct = Math.min(100, Math.max(0, Math.round(progress)));
  const r = 46;
  const cx = 58;
  const cy = 58;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - pct / 100);

  return (
    <div className="debate-progress-ring">
      <div className="debate-progress-spinner" aria-hidden />
      <svg className="debate-progress-svg" viewBox="0 0 116 116" role="img" aria-label={`Overall progress ${pct}%`}>
        <circle className="debate-progress-track" cx={cx} cy={cy} r={r} />
        <circle
          className="debate-progress-arc"
          cx={cx}
          cy={cy}
          r={r}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          transform={`rotate(-90 ${cx} ${cy})`}
        />
      </svg>
      <div className="debate-progress-center">
        <span className="debate-progress-number">{pct}</span>
        <span className="debate-progress-percent">%</span>
      </div>
      <ul className="debate-phase-legend">
        <li>感知</li>
        <li>博弈</li>
        <li>定型</li>
        <li>校验</li>
        <li>执行</li>
      </ul>
    </div>
  );
}
