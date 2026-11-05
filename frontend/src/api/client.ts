/**
 * API client with automatic access-token refresh.
 *
 * Tokens are held in memory (access) and localStorage (refresh) so a page
 * reload keeps the session, while the short-lived access token is never
 * persisted. A 401 triggers a single refresh-and-retry.
 */
import type { TokenResponse, User } from "./types";

const REFRESH_KEY = "sentinel.refresh";

let accessToken: string | null = null;
let currentUser: User | null = null;
let refreshPromise: Promise<boolean> | null = null;

export const auth = {
  get user() { return currentUser; },
  get isAuthenticated() { return !!accessToken; },
  getRefresh() { try { return localStorage.getItem(REFRESH_KEY); } catch { return null; } },
  setSession(t: TokenResponse) {
    accessToken = t.access_token;
    currentUser = t.user;
    try { localStorage.setItem(REFRESH_KEY, t.refresh_token); } catch { /* ignore */ }
  },
  setUser(u: User) { currentUser = u; },
  clear() {
    accessToken = null; currentUser = null;
    try { localStorage.removeItem(REFRESH_KEY); } catch { /* ignore */ }
  },
};

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function refreshTokens(): Promise<boolean> {
  const refresh = auth.getRefresh();
  if (!refresh) return false;
  if (!refreshPromise) {
    refreshPromise = fetch("/api/auth/refresh", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refresh }),
    }).then(async (r) => {
      if (!r.ok) { auth.clear(); return false; }
      auth.setSession(await r.json());
      return true;
    }).catch(() => false).finally(() => { refreshPromise = null; });
  }
  return refreshPromise;
}

async function raw<T>(method: string, path: string, body?: unknown, retry = true): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (accessToken) headers["Authorization"] = `Bearer ${accessToken}`;
  const res = await fetch(path, {
    method, headers, body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && retry && auth.getRefresh()) {
    if (await refreshTokens()) return raw<T>(method, path, body, false);
    auth.clear();
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { const j = await res.json(); detail = j.detail ?? detail; } catch { /* ignore */ }
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  get: <T>(p: string) => raw<T>("GET", p),
  post: <T>(p: string, b?: unknown) => raw<T>("POST", p, b),
  put: <T>(p: string, b?: unknown) => raw<T>("PUT", p, b),
  del: <T>(p: string, b?: unknown) => raw<T>("DELETE", p, b),

  async login(username: string, password: string) {
    const r = await fetch("/api/auth/login", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!r.ok) {
      let d = "login failed";
      try { d = (await r.json()).detail ?? d; } catch { /* ignore */ }
      throw new ApiError(r.status, d);
    }
    const t: TokenResponse = await r.json();
    auth.setSession(t);
    return t;
  },
  async restore(): Promise<boolean> {
    if (!auth.getRefresh()) return false;
    if (!(await refreshTokens())) return false;
    try { auth.setUser(await raw<User>("GET", "/api/auth/profile")); } catch { return false; }
    return true;
  },
  async logout() {
    try { await raw("POST", "/api/auth/logout", { refresh_token: auth.getRefresh() }); }
    catch { /* ignore */ }
    auth.clear();
  },
};

export function wsUrl(): string {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}/api/ws?token=${encodeURIComponent(accessToken ?? "")}`;
}
