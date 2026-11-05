import { riskColor } from "../lib/format";

export function RiskGauge({ score, level, size = 180 }: { score: number; level: string; size?: number }) {
  const r = size / 2 - 14;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const color = riskColor(level);
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1e2a3a" strokeWidth={12} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={12}
          strokeLinecap="round" strokeDasharray={circ}
          strokeDashoffset={circ * (1 - pct)}
          style={{ transition: "stroke-dashoffset 0.6s ease, stroke 0.4s ease",
                   filter: `drop-shadow(0 0 8px ${color}66)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className="text-4xl font-bold" style={{ color }}>{score.toFixed(0)}</div>
        <div className="text-xs uppercase tracking-widest mt-1" style={{ color }}>{level}</div>
        <div className="text-[10px] text-ink-faint mt-0.5">risk score</div>
      </div>
    </div>
  );
}
