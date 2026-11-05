import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, auth } from "../api/client";
import type { Role, User } from "../api/types";

interface AuthCtx {
  user: User | null;
  ready: boolean;
  login: (u: string, p: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (role: Role) => boolean;
}

const Ctx = createContext<AuthCtx>(null!);
const RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(auth.user);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    api.restore().then((ok) => { if (ok) setUser(auth.user); }).finally(() => setReady(true));
  }, []);

  const value: AuthCtx = {
    user, ready,
    login: async (u, p) => { const t = await api.login(u, p); setUser(t.user); },
    logout: async () => { await api.logout(); setUser(null); },
    can: (role) => !!user && RANK[user.role] >= RANK[role],
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);
