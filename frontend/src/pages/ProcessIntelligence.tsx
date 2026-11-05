import { useState } from "react";
import { Cpu } from "lucide-react";
import { api } from "../api/client";
import type { ProcessRow } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { Card, Pill, Spinner, StatCard } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { fmtAgo, fmtBytes } from "../lib/format";

export default function ProcessIntelligence() {
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const procs = usePolling<ProcessRow[]>(
    () => api.get(`/api/processes?running_only=true&suspicious_only=${suspiciousOnly}&limit=300`),
    5000, [suspiciousOnly]);

  if (procs.loading && !procs.data) return <Spinner />;
  const rows = procs.data ?? [];
  const suspicious = rows.filter((p) => p.suspicious).length;

  return (
    <div>
      <PageHeader title="Process Intelligence" subtitle="Running processes and file-modification attribution"
        actions={
          <label className="flex items-center gap-2 text-sm text-ink-dim cursor-pointer">
            <input type="checkbox" checked={suspiciousOnly}
              onChange={(e) => setSuspiciousOnly(e.target.checked)} /> suspicious only
          </label>} />

      <div className="grid sm:grid-cols-3 gap-4 mb-6">
        <StatCard label="Tracked Processes" value={rows.length} icon={<Cpu size={22} />} />
        <StatCard label="Suspicious" value={suspicious} accent={suspicious ? "#f97316" : undefined} />
        <StatCard label="Total Files Modified"
          value={rows.reduce((n, p) => n + p.files_modified, 0).toLocaleString()} />
      </div>

      <Card>
        <h2 className="font-medium mb-3">Process Activity</h2>
        <DataTable<ProcessRow> rows={rows} keyFn={(p) => p.id} empty="No process telemetry yet."
          columns={[
            { key: "name", header: "Process", render: (p) => (
              <div><div className="text-sm">{p.process_name} <span className="text-ink-faint">#{p.process_id}</span></div>
                {p.executable_path && <div className="font-mono text-[11px] text-ink-faint truncate max-w-[260px]"
                  title={p.executable_path}>{p.executable_path}</div>}</div> ) },
            { key: "user", header: "User", render: (p) => <span className="text-xs">{p.username ?? "—"}</span> },
            { key: "ppid", header: "Parent", render: (p) => <span className="text-ink-faint text-xs">
              {p.parent_process_id ?? "—"}</span> },
            { key: "files", header: "Files", render: (p) => p.files_modified },
            { key: "write", header: "Write Rate", render: (p) => p.write_bytes_rate
              ? `${fmtBytes(p.write_bytes_rate)}/s` : "—" },
            { key: "flag", header: "State", render: (p) => p.suspicious
              ? <Pill text="suspicious" tone="bad" /> : <Pill text="normal" tone="good" /> },
            { key: "reasons", header: "Reasons", render: (p) => (
              <span className="text-xs text-ink-faint">{(p.suspicion_reasons ?? []).join("; ") || "—"}</span> ) },
            { key: "seen", header: "Last Seen", render: (p) => <span className="text-ink-faint text-xs">
              {fmtAgo(p.last_seen)}</span> },
          ]} />
      </Card>
    </div>
  );
}
