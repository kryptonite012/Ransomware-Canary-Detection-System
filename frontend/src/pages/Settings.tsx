import { useEffect, useState } from "react";
import { FolderPlus, Save, UserPlus, KeyRound, Trash2 } from "lucide-react";
import { api } from "../api/client";
import type { Directory, Endpoint, User } from "../api/types";
import { usePolling } from "../hooks/usePolling";
import { useEndpoints } from "../hooks/useEndpoints";
import { useAuth } from "../context/auth";
import { Card, Empty, Pill, Spinner } from "../components/ui";
import { PageHeader } from "../components/PageHeader";
import { fmtTime } from "../lib/format";

interface ConfigResp {
  active_version: number | null; policy: Record<string, unknown> | null;
  published_at: string | null; history: { version: number; comment: string | null; created_at: string }[];
}

export default function SettingsPage() {
  const { can } = useAuth();
  const eps = useEndpoints();
  const [tab, setTab] = useState<"monitoring" | "policy" | "users">("monitoring");

  return (
    <div>
      <PageHeader title="Settings" subtitle="Monitoring, detection policy and user administration" />
      <div className="flex gap-2 mb-6 border-b border-bg-border">
        {(["monitoring", "policy", "users"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm border-b-2 -mb-px transition-colors ${tab === t
              ? "border-accent text-accent" : "border-transparent text-ink-dim hover:text-ink"}`}>
            {t[0].toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      {tab === "monitoring" && <MonitoringTab eps={eps.data ?? []} canEdit={can("analyst")} />}
      {tab === "policy" && <PolicyTab canEdit={can("admin")} />}
      {tab === "users" && <UsersTab canEdit={can("admin")} />}
    </div>
  );
}

function MonitoringTab({ eps, canEdit }: { eps: Endpoint[]; canEdit: boolean }) {
  const dirs = usePolling<Directory[]>(() => api.get("/api/monitoring/directories"), 8000);
  const [path, setPath] = useState("");
  const [epId, setEpId] = useState<number | "">("");
  const [recursive, setRecursive] = useState(true);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => { if (eps[0] && epId === "") setEpId(eps[0].id); }, [eps, epId]);

  async function add() {
    if (!path || epId === "") return;
    setMsg(null);
    try {
      await api.post("/api/monitoring/directories", { endpoint_id: epId, path, recursive });
      setPath(""); dirs.reload();
    } catch (e) { setMsg(e instanceof Error ? e.message : "failed"); }
  }
  async function remove(id: number) {
    try { await api.del(`/api/monitoring/directories/${id}`); dirs.reload(); }
    catch (e) { setMsg(e instanceof Error ? e.message : "failed"); }
  }

  if (dirs.loading && !dirs.data) return <Spinner />;
  return (
    <div className="space-y-6">
      {canEdit && (
        <Card>
          <h3 className="font-medium mb-3 flex items-center gap-2"><FolderPlus size={18} className="text-accent" />
            Add Monitored Directory</h3>
          <div className="grid sm:grid-cols-[1fr_auto_auto_auto] gap-3 items-end">
            <div>
              <label className="label">Directory path</label>
              <input className="input mt-1" placeholder="/home/user/Documents" value={path}
                onChange={(e) => setPath(e.target.value)} />
            </div>
            <div>
              <label className="label">Endpoint</label>
              <select className="input mt-1 !w-auto" value={epId}
                onChange={(e) => setEpId(Number(e.target.value))}>
                {eps.map((e) => <option key={e.id} value={e.id}>{e.hostname}</option>)}
              </select>
            </div>
            <label className="flex items-center gap-2 text-sm text-ink-dim pb-2">
              <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} />
              recursive</label>
            <button className="btn btn-primary" onClick={add} disabled={!path}>Add</button>
          </div>
          {msg && <div className="text-risk-critical text-sm mt-2">{msg}</div>}
          <p className="text-xs text-ink-faint mt-3">
            Registered directories are Ed25519-signed by the control plane; the agent applies them on its
            next config poll and deploys canaries automatically.</p>
        </Card>
      )}
      <Card>
        <h3 className="font-medium mb-3">Monitored Directories</h3>
        {(dirs.data ?? []).length === 0 ? <Empty>None registered.</Empty> : (
          <div className="space-y-2">
            {dirs.data!.map((d) => (
              <div key={d.id} className="flex items-center gap-3 p-2 rounded-lg bg-bg-soft/50">
                <Pill text={d.status} tone={d.status === "active" ? "good" : d.status === "rejected" ? "bad" : "default"} />
                <span className="font-mono text-xs flex-1 truncate">{d.directory_path}</span>
                {d.monitoring_enabled ? <span className="text-xs text-ink-faint">enabled</span>
                  : <span className="text-xs text-risk-high">disabled</span>}
                {canEdit && d.monitoring_enabled && (
                  <button className="btn btn-danger !py-1" onClick={() => remove(d.id)}>
                    <Trash2 size={14} /></button>)}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function PolicyTab({ canEdit }: { canEdit: boolean }) {
  const cfg = usePolling<ConfigResp>(() => api.get("/api/system/configuration"), 15000);
  const [text, setText] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [edited, setEdited] = useState(false);
  useEffect(() => {
    if (cfg.data && !edited) setText(JSON.stringify(cfg.data.policy ?? {}, null, 2));
  }, [cfg.data, edited]);

  async function publish() {
    setMsg(null);
    let policy: unknown;
    try { policy = JSON.parse(text); }
    catch { setMsg("invalid JSON"); return; }
    try {
      const r = await api.put<{ detail: string }>("/api/system/configuration",
        { policy, comment: "edited from console" });
      setMsg(r.detail); setEdited(false); cfg.reload();
    } catch (e) { setMsg(e instanceof Error ? e.message : "failed"); }
  }

  if (cfg.loading && !cfg.data) return <Spinner />;
  return (
    <div className="grid lg:grid-cols-3 gap-6">
      <Card className="lg:col-span-2">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-medium">Detection Policy (signed)</h3>
          <span className="text-xs text-ink-faint">
            active v{cfg.data?.active_version ?? "—"} · {fmtTime(cfg.data?.published_at ?? null)}</span>
        </div>
        <textarea className="input font-mono text-xs h-[420px]" spellCheck={false}
          value={text} disabled={!canEdit}
          onChange={(e) => { setText(e.target.value); setEdited(true); }} />
        {msg && <div className="text-sm mt-2 text-accent">{msg}</div>}
        {canEdit && (
          <button className="btn btn-primary mt-3" onClick={publish}>
            <Save size={16} /> Publish &amp; sign policy</button>
        )}
        <p className="text-xs text-ink-faint mt-2">
          Policy is validated against the schema and signed before agents accept it. Only policy sections
          (monitoring, entropy, canary, behavior, risk, response, retention) are allowed.</p>
      </Card>
      <Card>
        <h3 className="font-medium mb-3">Version History</h3>
        <div className="space-y-2">
          {(cfg.data?.history ?? []).map((h) => (
            <div key={h.version} className="p-2 rounded-lg bg-bg-soft/50">
              <div className="flex items-center justify-between">
                <span className="font-medium text-sm">v{h.version}</span>
                <span className="text-[11px] text-ink-faint">{fmtTime(h.created_at)}</span>
              </div>
              {h.comment && <div className="text-xs text-ink-dim">{h.comment}</div>}
            </div>
          ))}
          {!(cfg.data?.history ?? []).length && <Empty>No policy published yet.</Empty>}
        </div>
      </Card>
    </div>
  );
}

function UsersTab({ canEdit }: { canEdit: boolean }) {
  const users = usePolling<User[]>(() => api.get("/api/auth/users"), 20000);
  const [form, setForm] = useState({ username: "", email: "", password: "", role: "viewer" });
  const [msg, setMsg] = useState<string | null>(null);

  async function create() {
    setMsg(null);
    try {
      await api.post("/api/auth/users", form);
      setForm({ username: "", email: "", password: "", role: "viewer" });
      users.reload();
    } catch (e) { setMsg(e instanceof Error ? e.message : "failed"); }
  }

  if (!canEdit) return <Card><Empty>Administrator role required to manage users.</Empty></Card>;
  if (users.loading && !users.data) return <Spinner />;
  return (
    <div className="space-y-6">
      <Card>
        <h3 className="font-medium mb-3 flex items-center gap-2"><UserPlus size={18} className="text-accent" />
          Create User</h3>
        <div className="grid sm:grid-cols-4 gap-3">
          <input className="input" placeholder="username" value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })} />
          <input className="input" placeholder="email" value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <input className="input" type="password" placeholder="password (min 8)" value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <select className="input" value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}>
            {["viewer", "analyst", "admin"].map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </div>
        {msg && <div className="text-sm mt-2 text-risk-critical">{msg}</div>}
        <button className="btn btn-primary mt-3" onClick={create}
          disabled={!form.username || !form.email || form.password.length < 8}>
          <KeyRound size={16} /> Create</button>
      </Card>
      <Card>
        <h3 className="font-medium mb-3">Users</h3>
        <div className="space-y-2">
          {(users.data ?? []).map((u) => (
            <div key={u.id} className="flex items-center gap-3 p-2 rounded-lg bg-bg-soft/50">
              <span className="font-medium text-sm flex-1">{u.username}</span>
              <span className="text-xs text-ink-faint">{u.email}</span>
              <Pill text={u.role} tone={u.role === "admin" ? "warn" : "default"} />
              <span className="text-[11px] text-ink-faint">last login {fmtTime(u.last_login)}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
