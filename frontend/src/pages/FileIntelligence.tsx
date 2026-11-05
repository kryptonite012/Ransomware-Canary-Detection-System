import {
  Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis, CartesianGrid,
} from "recharts";
import { api } from "../api/client";
import type { Directory, EntropyRow, FileEvent, Statistics } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { Card, ErrorNote, Pill, Spinner } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { fmtAgo, fmtBytes, titleCase } from "../lib/format";

const PIE = ["#2dd4bf", "#60a5fa", "#a78bfa", "#f472b6", "#fbbf24", "#f97316", "#34d399", "#f87171"];

export default function FileIntelligence() {
  const dirs = usePolling<Directory[]>(() => api.get("/api/monitoring/directories"), 10000);
  const stats = usePolling<Statistics>(() => api.get("/api/dashboard/statistics"), 15000);
  const events = usePolling<FileEvent[]>(() => api.get("/api/detection/events?limit=40"), 6000);
  const entropy = usePolling<EntropyRow[]>(() => api.get("/api/detection/entropy-history?limit=40"), 8000);

  if (stats.loading && !stats.data) return <Spinner />;
  const cats = Object.entries(stats.data?.file_category_distribution ?? {})
    .map(([name, value]) => ({ name: titleCase(name), value })).sort((a, b) => b.value - a.value);
  const evTypes = Object.entries(stats.data?.event_type_distribution ?? {})
    .map(([name, value]) => ({ name: titleCase(name), value }));

  return (
    <div>
      <PageHeader title="File Intelligence" subtitle="Monitored directories, file activity and entropy" />
      {stats.error && <ErrorNote message={stats.error} />}

      <div className="grid lg:grid-cols-2 gap-6 mb-6">
        <Card>
          <h2 className="font-medium mb-3">File-type Distribution</h2>
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={cats} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90}
                  innerRadius={50} paddingAngle={2}>
                  {cats.map((_, i) => <Cell key={i} fill={PIE[i % PIE.length]} stroke="#0f141c" />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#121a25", border: "1px solid #1e2a3a",
                  borderRadius: 8, fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>
        <Card>
          <h2 className="font-medium mb-3">Event Types (24h)</h2>
          <div style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={evTypes} margin={{ left: -20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e2a3a" />
                <XAxis dataKey="name" stroke="#5b6b80" fontSize={11} />
                <YAxis stroke="#5b6b80" fontSize={11} />
                <Tooltip cursor={{ fill: "#1e2a3a55" }} contentStyle={{ background: "#121a25",
                  border: "1px solid #1e2a3a", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="value" fill="#2dd4bf" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>

      <Card className="mb-6">
        <h2 className="font-medium mb-3">Monitored Directories</h2>
        <DataTable<Directory> rows={dirs.data ?? []} keyFn={(d) => d.id}
          empty="No directories registered. Add one from Settings."
          columns={[
            { key: "path", header: "Path", render: (d) => <span className="font-mono text-xs">{d.directory_path}</span> },
            { key: "rec", header: "Recursive", render: (d) => d.recursive ? "yes" : "no" },
            { key: "status", header: "Status", render: (d) => (
              <Pill text={d.status} tone={d.status === "active" ? "good" : d.status === "rejected" ? "bad" : "default"} /> ) },
            { key: "prot", header: "Protected", render: (d) => d.protected ? <Pill text="protected" tone="warn" /> : "—" },
            { key: "detail", header: "Detail", render: (d) => <span className="text-ink-faint text-xs">{d.status_detail ?? "—"}</span> },
          ]} />
      </Card>

      <div className="grid lg:grid-cols-2 gap-6">
        <Card>
          <h2 className="font-medium mb-3">Suspicious Entropy Changes</h2>
          <DataTable<EntropyRow> rows={(entropy.data ?? []).filter((e) => e.suspicious).slice(0, 12)}
            keyFn={(e) => e.id} empty="No suspicious entropy changes."
            columns={[
              { key: "file", header: "File", render: (e) => <span className="font-mono text-xs truncate block max-w-[200px]"
                title={e.file_path}>{e.file_path.split("/").pop()}</span> },
              { key: "ent", header: "Entropy", render: (e) => (
                <span className="text-risk-high">{e.previous_entropy?.toFixed(1) ?? "?"}→{e.current_entropy.toFixed(1)}</span> ) },
              { key: "magic", header: "Header", render: (e) => e.magic_ok === false
                ? <Pill text="mismatch" tone="bad" /> : <Pill text="ok" tone="good" /> },
              { key: "when", header: "When", render: (e) => <span className="text-ink-faint text-xs">{fmtAgo(e.timestamp)}</span> },
            ]} />
        </Card>
        <Card>
          <h2 className="font-medium mb-3">Recent File Events</h2>
          <DataTable<FileEvent> rows={events.data ?? []} keyFn={(e) => e.id} empty="No file events yet."
            columns={[
              { key: "type", header: "Type", render: (e) => <Pill text={e.event_type}
                tone={e.event_type === "deleted" ? "bad" : "default"} /> },
              { key: "file", header: "File", render: (e) => <span className="font-mono text-xs truncate block max-w-[180px]"
                title={e.file_path}>{e.file_path.split("/").pop()}</span> },
              { key: "proc", header: "Process", render: (e) => e.process_name
                ? <span className="text-xs">{e.process_name} <span className="text-ink-faint">({e.attribution})</span></span> : "—" },
              { key: "size", header: "Size", render: (e) => <span className="text-xs">{fmtBytes(e.file_size)}</span> },
              { key: "when", header: "When", render: (e) => <span className="text-ink-faint text-xs">{fmtAgo(e.timestamp)}</span> },
            ]} />
        </Card>
      </div>
    </div>
  );
}
