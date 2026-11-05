import { api } from "../api/client";
import type { Endpoint } from "../api/types";
import { usePolling } from "./usePolling";

export function useEndpoints() {
  return usePolling<Endpoint[]>(() => api.get("/api/endpoints"), 15000);
}
