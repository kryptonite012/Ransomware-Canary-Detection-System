import { useState } from "react";
import { Radar, RefreshCw, ShieldCheck, Rocket } from "lucide-react";
import { api } from "../api/client";
import type { Canary, Endpoint } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { useEndpoints } from "../hooks/useEndpoints";
import { useAuth } from "../context/auth";
import { Card, Empty, Pill, Spinner, StatCard } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { fmtAgo, fmtTime, titleCase } from "../lib/format";

const STATUS_TONE: Record<string, "good" | "warn" | "bad" | "default"> = {
  active: "good", triggered: "bad", missing: "bad", regenerating: "warn", error: "bad", retired: "default",
};

export default function CanaryManagement() {
  const { can } = useAuth();
  const eps = useEndpoints();
  const [msg, setMsg] = useState<string | null>(null);
  const canaries = usePolling<Canary[]>(() => api.get("/api/canaries"), 6000);

  async function act(path: string, endpoint: Endpoint) {
    setMsg(null);
    try {
      const r = await api.post<{ detail: string }>(path, { endpoint_id: endpoint.id });
      setMsg(r.detail);
      setTimeout(() => canaries.reload(), 1000);
    } catch (e) { setMsg(e instanceof Error ? e.message : "command failed"); }
  }

  if (canaries.loading && !canaries.data) return <Spinner />;
  const rows = canaries.data ?? [];
  const active = rows.filter((c) => c.status === "active").length;
  const triggered = rows.reduce((n, c) => n + c.trigger_count, 0);
  const ep = eps.data?.[0];

  return (
    <div>
      <PageHeader title="Canary Management" subtitle="Decoy files that reveal ransomware on first touch"
        actions={can("analyst") && ep ? (
          <>
            <button className="btn" onClick={() => act("/api/canaries/verify", ep)}>
              <ShieldCheck size={16} /> Verify</button>
            <button className="btn" onClick={() => act("/api/canaries/regenerate", ep)}>
              <RefreshCw size={16} /> Regenerate</button>
            <button className="btn btn-primary" onClick={() => act("/api/canaries/deploy", ep)}>
              <Rocket size={16} /> Deploy</button>
          </>
        ) : undefined} />

      {msg && <div className="card card-pad mb-4 text-sm text-accent">{msg}</div>}

      <div className="grid sm:grid-cols-3 gap-4 mb-6">
        <StatCard label="Total Canaries" value={rows.length} icon={<Radar size={22} />} />
        <StatCard label="Active" value={active} accent="#22c55e" />
        <StatCard label="Total Triggers" value={triggered} accent={triggered ? "#ef4444" : undefined} />
      </div>

      <Card>
        <h2 className="font-medium mb-3">Canary Inventory</h2>
        {rows.length === 0 ? <Empty>No canaries deployed yet. Deploy from here or the agent config.</Empty> : (
          <DataTable<Canary> rows={rows} keyFn={(c) => c.id}
            columns={[
              { key: "name", header: "File", render: (c) => (
                <div><div className="text-sm">{c.file_path.split("/").pop()}</div>
                  <div className="font-mono text-[11px] text-ink-faint truncate max-w-[260px]"
                    title={c.directory}>{c.directory}</div></div> ) },
              { key: "type", header: "Type", render: (c) => <Pill text={c.canary_type} /> },
              { key: "status", header: "Status", render: (c) => <Pill text={titleCase(c.status)}
                tone={STATUS_TONE[c.status] ?? "default"} /> },
              { key: "trig", header: "Triggers", render: (c) => c.trigger_count > 0
                ? <span className="text-risk-critical font-medium">{c.trigger_count}</span> : "0" },
              { key: "inter", header: "Last Interaction", render: (c) => c.last_interaction
                ? <span>{titleCase(c.last_interaction_type ?? "")} · {fmtAgo(c.last_interaction)}</span>
                : <span className="text-ink-faint">none</span> },
              { key: "verif", header: "Last Verified", render: (c) => <span className="text-ink-faint text-xs">
                {fmtTime(c.last_verified)}</span> },
              { key: "gen", header: "Gen", render: (c) => <span className="text-ink-faint">#{c.generation}</span> },
            ]} />
        )}
      </Card>
    </div>
  );
}
