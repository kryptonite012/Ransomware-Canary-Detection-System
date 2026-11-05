import { useEffect, useRef, useState } from "react";
import { wsUrl } from "../api/client";

export interface WsMessage { type: string; data: any; }

export function useLiveFeed(onMessage: (m: WsMessage) => void) {
  const [connected, setConnected] = useState(false);
  const saved = useRef(onMessage);
  saved.current = onMessage;

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout>;
    let closed = false;

    const connect = () => {
      try { ws = new WebSocket(wsUrl()); } catch { return; }
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 3000);
      };
      ws.onerror = () => ws?.close();
      ws.onmessage = (ev) => {
        try { saved.current(JSON.parse(ev.data)); } catch { /* ignore */ }
      };
    };
    connect();
    return () => { closed = true; clearTimeout(retry); ws?.close(); };
  }, []);

  return { connected };
}
