import type { ReactNode } from "react";
import { riskColor, severityColor, titleCase } from "../lib/format";

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`card card-pad ${className}`}>{children}</div>;
}

export function StatCard({ label, value, sub, icon, accent }: {
  label: string; value: ReactNode; sub?: ReactNode; icon?: ReactNode; accent?: string;
}) {
  return (
    <div className="card card-pad flex items-start justify-between gap-3">
      <div className="min-w-0">
        <div className="label">{label}</div>
        <div className="text-2xl font-semibold mt-1 truncate" style={accent ? { color: accent } : undefined}>
          {value}
        </div>
        {sub && <div className="text-xs text-ink-dim mt-1 truncate">{sub}</div>}
      </div>
      {icon && <div className="text-ink-faint shrink-0">{icon}</div>}
    </div>
  );
}

export function RiskBadge({ level, score }: { level: string; score?: number }) {
  const c = riskColor(level);
  return (
    <span className="chip" style={{ background: `${c}1a`, color: c, border: `1px solid ${c}55` }}>
      {titleCase(level)}{score != null ? ` · ${score.toFixed(0)}` : ""}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const c = severityColor(severity);
  return (
    <span className="chip" style={{ background: `${c}1a`, color: c, border: `1px solid ${c}55` }}>
      {titleCase(severity)}
    </span>
  );
}

export function StatusDot({ ok, label }: { ok: boolean; label?: ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span className={`w-2 h-2 rounded-full ${ok ? "bg-risk-normal" : "bg-risk-critical"}`} />
      {label}
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="text-center text-ink-faint text-sm py-10">{children}</div>;
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-12 text-ink-faint">
      <div className="w-6 h-6 border-2 border-bg-border border-t-accent rounded-full animate-spin" />
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <div className="card card-pad border-risk-critical/40 bg-risk-critical/5 text-risk-critical text-sm">
      {message}
    </div>
  );
}

export function Pill({ text, tone = "default" }: { text: string; tone?: "default" | "good" | "warn" | "bad" }) {
  const tones: Record<string, string> = {
    default: "bg-bg-soft text-ink-dim border-bg-border",
    good: "bg-risk-normal/10 text-risk-normal border-risk-normal/40",
    warn: "bg-risk-elevated/10 text-risk-elevated border-risk-elevated/40",
    bad: "bg-risk-critical/10 text-risk-critical border-risk-critical/40",
  };
  return <span className={`chip border ${tones[tone]}`}>{text}</span>;
}
