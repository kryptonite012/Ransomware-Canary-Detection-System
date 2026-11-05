import { FormEvent, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { Shield, Lock, User as UserIcon } from "lucide-react";
import { useAuth } from "../context/auth";

export default function Login() {
  const { user, login } = useAuth();
  const nav = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try { await login(username, password); nav("/"); }
    catch (err) { setError(err instanceof Error ? err.message : "login failed"); }
    finally { setBusy(false); }
  }

  return (
    <div className="min-h-screen grid place-items-center p-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <div className="relative">
            <Shield className="text-accent" size={48} />
            <span className="absolute inset-0 rounded-full animate-pulseRing"
              style={{ boxShadow: "0 0 30px 6px rgba(45,212,191,0.4)" }} />
          </div>
          <h1 className="text-2xl font-bold mt-4 tracking-wide">PROJECT SENTINEL</h1>
          <p className="text-ink-faint text-sm mt-1">Ransomware Detection Console</p>
        </div>
        <form onSubmit={submit} className="card card-pad space-y-4">
          <div>
            <label className="label">Username</label>
            <div className="relative mt-1">
              <UserIcon size={16} className="absolute left-3 top-3 text-ink-faint" />
              <input className="input pl-9" value={username} autoFocus
                onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
            </div>
          </div>
          <div>
            <label className="label">Password</label>
            <div className="relative mt-1">
              <Lock size={16} className="absolute left-3 top-3 text-ink-faint" />
              <input className="input pl-9" type="password" value={password}
                onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            </div>
          </div>
          {error && <div className="text-risk-critical text-sm">{error}</div>}
          <button className="btn btn-primary w-full justify-center" disabled={busy || !username || !password}>
            {busy ? "Authenticating…" : "Sign in"}
          </button>
        </form>
        <p className="text-center text-ink-faint text-xs mt-4">
          Authorized personnel only · activity is audited
        </p>
      </div>
    </div>
  );
}
