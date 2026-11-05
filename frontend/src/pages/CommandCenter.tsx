import { useState } from "react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import {
  AlertTriangle, FileText, Radar, Cpu, FolderLock, ShieldCheck, Server, Bell,
} from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { ActivityPoint, Alert, Incident, Overview } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { Card, Empty, ErrorNote, RiskBadge, SeverityBadge, Spinner, StatCard } from "../components/ui";
import { RiskGauge } from "../components/RiskGauge";
import { fmtAgo, fmtNum, fmtTime, titleCase } from "../lib/format";

const STATUS_LABEL: Record<string, { text: string; tone: string }> = {
  normal: { text: "All Systems Normal", tone: "#22c55e" },
  elevated: { text: "Elevated Monitoring", tone: "#eab308" },
  under_attack: { text: "Active Threat Detected", tone: "#ef4444" },
  agent_offline: { text: "Agent Offline", tone: "#f97316" },
};

export default function CommandCenter() {
  const [hours] = useState(24);
  const ov = usePolling<Overview>(() => api.get("/api/dashboard/overview"), 5000);
  const act = usePolling<ActivityPoint[]>(() => api.get(`/api/dashboard/activity?hours=${hours}`), 15000);
  const alerts = usePolling<Alert[]>(() => api.get("/api/detection/alerts?limit=6"), 5000);
  const incidents = usePolling<Incident[]>(() => api.get("/api/incidents?limit=5"), 8000);

  if (ov.loading && !ov.data) return <Spinner />;
  if (ov.error && !ov.data) return <ErrorNote message={ov.error} />;
  const o = ov.data!;
  const status = STATUS_LABEL[o.status] ?? STATUS_LABEL.normal;
  const chart = (act.data ?? []).map((p) => ({
    t: new Date(p.bucket_start).getHours() + ":00", events: p.events, alerts: p.alerts,
    critical: p.critical_alerts,
  }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold">Command Center</h1>
          <p className="text-ink-dim text-sm">Endpoint security posture and live threat activity</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border"
          style={{ borderColor: `${status.tone}55`, background: `${status.tone}14`, color: status.tone }}>
          <span className="w-2 h-2 rounded-full animate-pulseRing" style={{ background: status.tone }} />
          <span className="text-sm font-medium">{status.text}</span>
        </div>
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        <Card className="flex flex-col items-center justify-center gap-3">
          <RiskGauge score={o.risk_score} level={o.risk_level} />
          <div className="text-center">
            <div className="text-xs text-ink-faint">
              {o.endpoints_online}/{o.endpoints_total} agents online · peak {o.risk_details?.peak_score ?? 0}
            </div>
          </div>
        </Card>

        <div className="lg:col-span-2 grid sm:grid-cols-2 gap-4">
          <StatCard label="Monitored Files" value={fmtNum(o.monitored_files)}
            sub={`${fmtNum(o.files_modified_last_hour)} changed last hour`} icon={<FileText size={22} />} />
          <StatCard label="Active Canaries" value={fmtNum(o.active_canaries)}
            sub={o.triggered_canaries ? `${o.triggered_canaries} triggered` : "all intact"}
            icon={<Radar size={22} />} accent={o.triggered_canaries ? "#ef4444" : undefined} />
          <StatCard label="Suspicious Processes" value={fmtNum(o.suspicious_processes)}
            sub="flagged by behavior" icon={<Cpu size={22} />}
            accent={o.suspicious_processes ? "#f97316" : undefined} />
          <StatCard label="Open Incidents" value={fmtNum(o.open_incidents)}
            sub={`${fmtNum(o.total_alerts)} total alerts`} icon={<AlertTriangle size={22} />}
            accent={o.open_incidents ? "#ef4444" : undefined} />
          <StatCard label="Protected Directories" value={fmtNum(o.protected_directories)}
            sub={`${fmtNum(o.monitored_directories)} monitored`} icon={<FolderLock size={22} />} />
          <StatCard label="Alerts (24h)" value={fmtNum(o.alerts_last_24h)}
            sub={`${fmtNum(o.open_alerts)} open`} icon={<Bell size={22} />} />
        </div>
      </div>

      <Card>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-medium flex items-center gap-2"><ShieldCheck size={18} className="text-accent" />
            Threat Activity Timeline</h2>
          <span className="text-xs text-ink-faint">last {hours}h</span>
        </div>
        <div style={{ height: 220 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chart} margin={{ left: -20, right: 8, top: 4 }}>
              <defs>
                <linearGradient id="gEvents" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2dd4bf" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#2dd4bf" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gAlerts" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2a3a" />
              <XAxis dataKey="t" stroke="#5b6b80" fontSize={11} tickLine={false} />
              <YAxis stroke="#5b6b80" fontSize={11} tickLine={false} />
              <Tooltip contentStyle={{ background: "#121a25", border: "1px solid #1e2a3a",
                borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="events" stroke="#2dd4bf" fill="url(#gEvents)" name="File events" />
              <Area type="monotone" dataKey="alerts" stroke="#ef4444" fill="url(#gAlerts)" name="Alerts" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <div className="grid lg:grid-cols-2 gap-6">
        <Card>
          <h2 className="font-medium mb-3 flex items-center gap-2">
            <Bell size={18} className="text-accent" /> Recent Alerts</h2>
          {(alerts.data ?? []).length === 0 ? <Empty>No alerts — endpoint is quiet.</Empty> : (
            <div className="space-y-2">
              {alerts.data!.map((a) => (
                <div key={a.id} className="flex items-start gap-3 p-2 rounded-lg hover:bg-bg-soft">
                  <SeverityBadge severity={a.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="text-sm truncate">{a.title}</div>
                    <div className="text-xs text-ink-faint">{titleCase(a.alert_type)} · {fmtAgo(a.timestamp)}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card>
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-medium flex items-center gap-2">
              <AlertTriangle size={18} className="text-accent" /> Recent Incidents</h2>
            <Link to="/incidents" className="text-xs text-accent hover:underline">view all</Link>
          </div>
          {(incidents.data ?? []).length === 0 ? <Empty>No incidents recorded.</Empty> : (
            <div className="space-y-2">
              {incidents.data!.map((i) => (
                <Link key={i.id} to={`/incidents/${i.id}`}
                  className="flex items-center gap-3 p-2 rounded-lg hover:bg-bg-soft">
                  <SeverityBadge severity={i.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="text-sm truncate">{i.title}</div>
                    <div className="text-xs text-ink-faint">
                      {titleCase(i.response_status)} · {fmtTime(i.created_at)}</div>
                  </div>
                  <RiskBadge level={i.severity} score={i.risk_score} />
                </Link>
              ))}
            </div>
          )}
        </Card>
      </div>

      <div className="flex items-center gap-2 text-xs text-ink-faint">
        <Server size={14} /> Overview refreshed {fmtAgo(o.generated_at)}
      </div>
    </div>
  );
}
