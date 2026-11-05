import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { AlertTriangle, CheckCircle2, ShieldX, Undo2, Play } from "lucide-react";
import { api } from "../api/client";
import type { Incident, IncidentDetail, ResponseAction } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { useAuth } from "../context/auth";
import { Card, Empty, Pill, RiskBadge, SeverityBadge, Spinner } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { fmtTime, titleCase } from "../lib/format";

const ACTION_TONE: Record<string, "good" | "warn" | "bad" | "default"> = {
  completed: "good", rolled_back: "good", pending_approval: "warn", approved: "warn",
  executing: "warn", failed: "bad", rejected: "bad", expired: "default",
};

export default function IncidentResponse() {
  const { id } = useParams();
  const nav = useNavigate();
  const { can } = useAuth();
  const list = usePolling<Incident[]>(() => api.get("/api/incidents?limit=100"), 8000);
  const [selId, setSelId] = useState<number | null>(id ? Number(id) : null);
  useEffect(() => { if (id) setSelId(Number(id)); }, [id]);

  const detail = usePolling<IncidentDetail | null>(
    () => selId ? api.get(`/api/incidents/${selId}`) : Promise.resolve(null), 5000, [selId]);

  async function call(path: string, body?: unknown) {
    try { await api.post(path, body); detail.reload(); list.reload(); }
    catch (e) { alert(e instanceof Error ? e.message : "action failed"); }
  }

  if (list.loading && !list.data) return <Spinner />;
  const rows = list.data ?? [];
  const d = detail.data;

  return (
    <div>
      <PageHeader title="Incident Response" subtitle="Investigate, contain and resolve ransomware incidents" />
      <div className="grid lg:grid-cols-5 gap-6">
        <Card className="lg:col-span-2 !p-0 overflow-hidden">
          <div className="p-4 border-b border-bg-border font-medium flex items-center gap-2">
            <AlertTriangle size={18} className="text-accent" /> Incidents ({rows.length})</div>
          <div className="max-h-[70vh] overflow-y-auto">
            {rows.length === 0 ? <Empty>No incidents.</Empty> : rows.map((i) => (
              <button key={i.id} onClick={() => { setSelId(i.id); nav(`/incidents/${i.id}`); }}
                className={`w-full text-left p-3 border-b border-bg-border/60 hover:bg-bg-soft
                  ${selId === i.id ? "bg-bg-soft" : ""}`}>
                <div className="flex items-center justify-between gap-2">
                  <SeverityBadge severity={i.severity} />
                  <Pill text={titleCase(i.response_status)}
                    tone={i.response_status === "resolved" ? "good" : "warn"} />
                </div>
                <div className="text-sm mt-1">{i.title}</div>
                <div className="text-[11px] text-ink-faint">#{i.id} · {fmtTime(i.created_at)}</div>
              </button>
            ))}
          </div>
        </Card>

        <div className="lg:col-span-3 space-y-6">
          {!d ? <Empty>Select an incident.</Empty> : (
            <>
              <Card>
                <div className="flex items-start justify-between gap-3 flex-wrap">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={d.incident.severity} />
                      <RiskBadge level={d.incident.severity} score={d.incident.risk_score} />
                      <Pill text={titleCase(d.incident.response_status)} />
                    </div>
                    <h2 className="text-lg font-medium">{d.incident.title}</h2>
                    {d.incident.summary && <p className="text-ink-dim text-sm mt-1">{d.incident.summary}</p>}
                  </div>
                </div>
                {can("analyst") && d.incident.response_status !== "resolved" && (
                  <div className="flex flex-wrap gap-2 mt-4">
                    <button className="btn" onClick={() => call(`/api/incidents/${d.incident.id}/acknowledge`, {})}>
                      Acknowledge</button>
                    <button className="btn btn-primary"
                      onClick={() => call(`/api/incidents/${d.incident.id}/resolve`, { note: "resolved from console" })}>
                      <CheckCircle2 size={15} /> Resolve</button>
                  </div>
                )}
              </Card>

              <div className="grid sm:grid-cols-2 gap-4">
                <Card>
                  <h3 className="font-medium mb-2 text-sm">Affected Files ({d.incident.affected_files?.length ?? 0})</h3>
                  <ul className="font-mono text-[11px] space-y-1 text-ink-dim max-h-40 overflow-y-auto">
                    {(d.incident.affected_files ?? []).map((f, i) => <li key={i} className="truncate" title={f}>{f}</li>)}
                    {!d.incident.affected_files?.length && <li className="text-ink-faint">none</li>}
                  </ul>
                </Card>
                <Card>
                  <h3 className="font-medium mb-2 text-sm">Processes ({d.incident.affected_processes?.length ?? 0})</h3>
                  <ul className="text-xs space-y-1 text-ink-dim max-h-40 overflow-y-auto">
                    {(d.incident.affected_processes ?? []).map((p, i) => (
                      <li key={i}>{p.name} <span className="text-ink-faint">#{p.pid}</span></li>))}
                    {!d.incident.affected_processes?.length && <li className="text-ink-faint">none</li>}
                  </ul>
                </Card>
              </div>

              <Card>
                <h3 className="font-medium mb-3">Response Actions</h3>
                {d.actions.length === 0 ? <Empty>No response actions.</Empty> : (
                  <div className="space-y-2">
                    {d.actions.map((a: ResponseAction) => (
                      <div key={a.id} className="flex items-center gap-3 p-2 rounded-lg bg-bg-soft/50">
                        <Pill text={titleCase(a.status)} tone={ACTION_TONE[a.status] ?? "default"} />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm">{titleCase(a.action_type)}</div>
                          <div className="text-[11px] text-ink-faint truncate">{a.reason}</div>
                        </div>
                        {can("admin") && a.status === "pending_approval" && (
                          <div className="flex gap-1">
                            <button className="btn btn-primary !py-1" title="Approve"
                              onClick={() => call(`/api/actions/${a.id}/approve`)}><Play size={14} /></button>
                            <button className="btn btn-danger !py-1" title="Reject"
                              onClick={() => call(`/api/actions/${a.id}/reject`)}><ShieldX size={14} /></button>
                          </div>
                        )}
                        {can("admin") && a.status === "completed" && a.action_type !== "terminate_process" && (
                          <button className="btn !py-1" title="Roll back"
                            onClick={() => call(`/api/actions/${a.id}/rollback`)}><Undo2 size={14} /></button>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </Card>

              <Card>
                <h3 className="font-medium mb-2 text-sm">Preserved Evidence ({d.evidence.length})</h3>
                <ul className="text-xs space-y-1 text-ink-dim max-h-40 overflow-y-auto">
                  {d.evidence.map((e) => (
                    <li key={e.id} className="flex justify-between gap-2">
                      <span className="truncate font-mono">{e.original_path ?? e.item_type}</span>
                      <span className="text-ink-faint shrink-0">{e.sha256 ? e.sha256.slice(0, 10) : e.item_type}</span>
                    </li>))}
                  {!d.evidence.length && <li className="text-ink-faint">no evidence preserved</li>}
                </ul>
              </Card>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
