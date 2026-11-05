import type { RiskLevel, Severity } from "../api/types";

export const RISK_COLORS: Record<RiskLevel, string> = {
  normal: "#22c55e", low: "#84cc16", elevated: "#eab308", high: "#f97316", critical: "#ef4444",
};
export const SEVERITY_COLORS: Record<Severity, string> = {
  info: "#60a5fa", low: "#84cc16", medium: "#eab308", high: "#f97316", critical: "#ef4444",
};

export function riskColor(level: string): string {
  return RISK_COLORS[level as RiskLevel] ?? "#8b9bb0";
}
export function severityColor(sev: string): string {
  return SEVERITY_COLORS[sev as Severity] ?? "#8b9bb0";
}

export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "—";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}
export function fmtNum(n: number | null | undefined): string {
  if (n == null) return "—";
  return n.toLocaleString();
}
export function fmtTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit",
    minute: "2-digit", second: "2-digit" });
}
export function fmtAgo(ts: string | null | undefined): string {
  if (!ts) return "never";
  const d = new Date(ts).getTime();
  if (isNaN(d)) return "never";
  const s = Math.max(0, (Date.now() - d) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
export function titleCase(s: string): string {
  return s.replace(/[_-]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
