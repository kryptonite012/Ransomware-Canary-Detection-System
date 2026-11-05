import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity, AlertTriangle, Database, FileSearch, Fingerprint, LayoutDashboard, LogOut, Radar,
  Settings, Shield, ShieldAlert, Cpu, Menu, X,
} from "lucide-react";
import { useAuth } from "../context/auth";
import { useLiveFeed } from "../hooks/useWebSocket";
import { StatusDot } from "../components/ui";

const NAV = [
  { to: "/", label: "Command Center", icon: LayoutDashboard, end: true },
  { to: "/files", label: "File Intelligence", icon: FileSearch },
  { to: "/canaries", label: "Canary Management", icon: Radar },
  { to: "/processes", label: "Process Intelligence", icon: Cpu },
  { to: "/threats", label: "Threat Detection", icon: ShieldAlert },
  { to: "/incidents", label: "Incident Response", icon: AlertTriangle },
  { to: "/forensics", label: "Forensics", icon: Fingerprint },
  { to: "/settings", label: "Settings", icon: Settings },
];

export default function DashboardLayout() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  const { connected } = useLiveFeed(() => {});

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className={`fixed z-30 inset-y-0 left-0 w-64 bg-bg-soft/95 border-r border-bg-border
        backdrop-blur transform transition-transform lg:translate-x-0
        ${open ? "translate-x-0" : "-translate-x-full"}`}>
        <div className="h-16 flex items-center gap-2 px-5 border-b border-bg-border">
          <Shield className="text-accent" size={22} />
          <div>
            <div className="font-semibold tracking-wide leading-tight">SENTINEL</div>
            <div className="text-[10px] text-ink-faint tracking-widest">RANSOMWARE DEFENSE</div>
          </div>
        </div>
        <nav className="p-3 space-y-1">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} onClick={() => setOpen(false)}
              className={({ isActive }) => `nav-link ${isActive ? "nav-link-active" : ""}`}>
              <n.icon size={18} /> {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="absolute bottom-0 inset-x-0 p-4 border-t border-bg-border">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <div className="text-sm font-medium truncate">{user?.username}</div>
              <div className="text-[11px] text-ink-faint uppercase">{user?.role}</div>
            </div>
            <button className="btn !px-2" title="Log out"
              onClick={async () => { await logout(); nav("/login"); }}>
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </aside>

      {open && <div className="fixed inset-0 bg-black/50 z-20 lg:hidden" onClick={() => setOpen(false)} />}

      {/* Main */}
      <div className="flex-1 lg:ml-64 min-w-0">
        <header className="h-16 sticky top-0 z-10 bg-bg/80 backdrop-blur border-b border-bg-border
          flex items-center justify-between px-4 lg:px-6">
          <button className="btn !px-2 lg:hidden" onClick={() => setOpen((o) => !o)}>
            {open ? <X size={18} /> : <Menu size={18} />}
          </button>
          <div className="flex items-center gap-2 text-ink-dim text-sm">
            <Database size={16} /> Security Operations Console
          </div>
          <div className="flex items-center gap-4">
            <StatusDot ok={connected} label={<span className="text-xs text-ink-dim">
              {connected ? "live" : "reconnecting"}</span>} />
            <Activity size={16} className="text-accent" />
          </div>
        </header>
        <main className="p-4 lg:p-6 max-w-[1500px] mx-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
