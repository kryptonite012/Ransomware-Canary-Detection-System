import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, auth } from "../api/client";

export function usePolling<T>(fetcher: () => Promise<T>, intervalMs = 5000, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const savedFetcher = useRef(fetcher);
  savedFetcher.current = fetcher;

  const load = useCallback(async () => {
    try {
      const d = await savedFetcher.current();
      setData(d);
      setError(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) { auth.clear(); location.reload(); return; }
      setError(e instanceof Error ? e.message : "request failed");
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    let active = true;
    load();
    const id = setInterval(() => { if (active) load(); }, intervalMs);
    return () => { active = false; clearInterval(id); };
  }, [load, intervalMs]);

  return { data, error, loading, reload: load };
}
