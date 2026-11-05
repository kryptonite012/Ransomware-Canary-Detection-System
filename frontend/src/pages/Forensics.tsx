import { Fingerprint, ShieldCheck, ShieldX } from "lucide-react";
import { api } from "../api/client";
import type { Evidence } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { Card, Pill, Spinner } from "../components/ui";
import { DataTable } from "../components/DataTable";
import { PageHeader } from "../components/PageHeader";
import { fmtBytes, fmtTime, titleCase } from "../lib/format";

interface AuditRow {
  id: number; user: string | null; action: string; resource: string; result: string;
  ip: string | null; timestamp: string; details: Record<string, unknown> | null;
}
interface AuditVerify { entries: number; valid: boolean; broken_entry_ids: number[]; }

export default function Forensics() {
  const evidence = usePolling<Evidence[]>(() => api.get("/api/forensics/evidence?limit=100"), 10000);
  const audit = usePolling<AuditRow[]>(() => api.get("/api/forensics/audit?limit=100"), 10000);
  const verify = usePolling<AuditVerify>(() => api.get("/api/forensics/audit/verify"), 30000);

  if (audit.loading && !audit.data) return <Spinner />;

  return (
    <div>
      <PageHeader title="Forensics" subtitle="Evidence vault and tamper-evident audit trail"
        actions={verify.data && (
          <span className={`chip border ${verify.data.valid
            ? "bg-risk-normal/10 text-risk-normal border-risk-normal/40"
            : "bg-risk-critical/10 text-risk-critical border-risk-critical/40"}`}>
            {verify.data.valid ? <ShieldCheck size={14} /> : <ShieldX size={14} />}
            audit chain {verify.data.valid ? "verified" : "BROKEN"} ({verify.data.entries})
          </span>)} />

      <Card className="mb-6">
        <h2 className="font-medium mb-3 flex items-center gap-2">
          <Fingerprint size={18} className="text-accent" /> Preserved Evidence</h2>
        <DataTable<Evidence> rows={evidence.data ?? []} keyFn={(e) => e.id}
          empty="No evidence preserved yet."
          columns={[
            { key: "type", header: "Type", render: (e) => <Pill text={titleCase(e.item_type)} /> },
            { key: "path", header: "Original Path", render: (e) => <span className="font-mono text-xs truncate
              block max-w-[320px]" title={e.original_path ?? ""}>{e.original_path ?? "—"}</span> },
            { key: "hash", header: "SHA-256", render: (e) => <span className="font-mono text-[11px] text-ink-faint">
              {e.sha256 ? e.sha256.slice(0, 16) + "…" : "—"}</span> },
            { key: "size", header: "Size", render: (e) => <span className="text-xs">{fmtBytes(e.size)}</span> },
            { key: "when", header: "Collected", render: (e) => <span className="text-ink-faint text-xs">
              {fmtTime(e.created_at)}</span> },
          ]} />
      </Card>

      <Card>
        <h2 className="font-medium mb-3">Audit Log</h2>
        <DataTable<AuditRow> rows={audit.data ?? []} keyFn={(r) => r.id} empty="No audit entries."
          columns={[
            { key: "id", header: "#", render: (r) => <span className="text-ink-faint font-mono text-xs">{r.id}</span> },
            { key: "user", header: "User", render: (r) => r.user ?? "—" },
            { key: "action", header: "Action", render: (r) => <span className="font-mono text-xs">{r.action}</span> },
            { key: "res", header: "Resource", render: (r) => <span className="font-mono text-xs truncate block
              max-w-[220px]" title={r.resource}>{r.resource}</span> },
            { key: "result", header: "Result", render: (r) => <Pill text={r.result}
              tone={r.result === "success" ? "good" : "bad"} /> },
            { key: "ip", header: "IP", render: (r) => <span className="text-xs text-ink-faint">{r.ip ?? "—"}</span> },
            { key: "when", header: "When", render: (r) => <span className="text-ink-faint text-xs">
              {fmtTime(r.timestamp)}</span> },
          ]} />
      </Card>
    </div>
  );
}
