import { useState } from "react";
import { ShieldAlert, ThumbsDown, ThumbsUp } from "lucide-react";
import { api } from "../api/client";
import type { Alert, Endpoint } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { useEndpoints } from "../hooks/useEndpoints";
import { useAuth } from "../context/auth";
import { Card, Empty, RiskBadge, SeverityBadge, Spinner } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { fmtAgo, riskColor, titleCase } from "../lib/format";

export default function ThreatDetection() {
  const { can } = useAuth();
  const eps = useEndpoints();
  const [sev, setSev] = useState("");
  const alerts = usePolling<Alert[]>(
    () => api.get(`/api/detection/alerts?limit=100${sev ? `&severity=${sev}` : ""}`), 5000, [sev]);
  const [sel, setSel] = useState<Alert | null>(null);

  async function feedback(a: Alert, verdict: "true_positive" | "false_positive") {
    try {
      await api.post(`/api/detection/alerts/${a.id}/feedback`, { feedback: verdict });
      alerts.reload();
    } catch { /* ignore */ }
  }

  if (alerts.loading && !alerts.data) return <Spinner />;
  const rows = alerts.data ?? [];
  const current = sel ?? rows[0] ?? null;
  const ep: Endpoint | undefined = eps.data?.find((e) => e.id === current?.endpoint_id);

  return (
    <div>
      <PageHeader title="Threat Detection" subtitle="Correlated detection signals with explanations"
        actions={
          <select className="input !w-auto" value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">all severities</option>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>} />

      <div className="grid lg:grid-cols-5 gap-6">
        <Card className="lg:col-span-2 !p-0 overflow-hidden">
          <div className="p-4 border-b border-bg-border font-medium flex items-center gap-2">
            <ShieldAlert size={18} className="text-accent" /> Alerts ({rows.length})</div>
          <div className="max-h-[70vh] overflow-y-auto">
            {rows.length === 0 ? <Empty>No alerts match.</Empty> : rows.map((a) => (
              <button key={a.id} onClick={() => setSel(a)}
                className={`w-full text-left p-3 border-b border-bg-border/60 hover:bg-bg-soft
                  ${current?.id === a.id ? "bg-bg-soft" : ""}`}>
                <div className="flex items-center justify-between gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="text-[11px] text-ink-faint">{fmtAgo(a.timestamp)}</span>
                </div>
                <div className="text-sm mt-1 truncate">{a.title}</div>
                <div className="text-[11px] text-ink-faint">{titleCase(a.alert_type)}
                  {a.feedback ? ` · ${titleCase(a.feedback)}` : ""}</div>
              </button>
            ))}
          </div>
        </Card>

        <div className="lg:col-span-3 space-y-6">
          {!current ? <Empty>Select an alert.</Empty> : (
            <>
              <Card>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={current.severity} />
                      {current.risk_level && <RiskBadge level={current.risk_level} score={current.risk_score} />}
                    </div>
                    <h2 className="text-lg font-medium">{current.title}</h2>
                    <p className="text-ink-dim text-sm mt-1">{current.description}</p>
                  </div>
                </div>
                {can("analyst") && (
                  <div className="flex gap-2 mt-4">
                    <button className="btn" onClick={() => feedback(current, "true_positive")}>
                      <ThumbsUp size={15} /> True positive</button>
                    <button className="btn" onClick={() => feedback(current, "false_positive")}>
                      <ThumbsDown size={15} /> False positive</button>
                  </div>
                )}
              </Card>

              <Card>
                <h3 className="font-medium mb-3">Contributing Signals</h3>
                {(current.signals ?? []).length === 0 ? <Empty>No signal breakdown.</Empty> : (
                  <div className="space-y-2">
                    {current.signals!.map((s, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <div className="w-28 shrink-0 text-xs text-ink-dim">{titleCase(s.signal_type)}</div>
                        <div className="flex-1 h-2 rounded bg-bg-soft overflow-hidden">
                          <div className="h-full rounded" style={{ width: `${Math.min(100, s.points)}%`,
                            background: riskColor(current.risk_level ?? "elevated") }} />
                        </div>
                        <div className="w-10 text-right text-xs font-mono">+{s.points.toFixed(0)}</div>
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              {current.file_paths && current.file_paths.length > 0 && (
                <Card>
                  <h3 className="font-medium mb-2">Affected Files</h3>
                  <ul className="font-mono text-xs space-y-1 text-ink-dim max-h-48 overflow-y-auto">
                    {current.file_paths.map((f, i) => <li key={i} className="truncate" title={f}>{f}</li>)}
                  </ul>
                </Card>
              )}

              {current.process_info && (
                <Card>
                  <h3 className="font-medium mb-2">Process</h3>
                  <pre className="text-xs text-ink-dim overflow-x-auto">
                    {JSON.stringify(current.process_info, null, 2)}</pre>
                </Card>
              )}

              {ep && <div className="text-xs text-ink-faint">Endpoint: {ep.hostname} ({ep.operating_system})</div>}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
