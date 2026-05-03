import type { Flow } from "../types";

export type WsStatus = "connecting" | "open" | "reconnecting";

export interface FlowSubscriberHandlers {
  onFlow: (flow: Flow) => void;
  onStatus?: (status: WsStatus) => void;
}

/**
 * Connect to the daemon's flow event stream. Auto-reconnects with
 * exponential-ish backoff. Returns a cleanup function.
 */
export function subscribeFlows(handlers: FlowSubscriberHandlers): () => void {
  let socket: WebSocket | null = null;
  let stopped = false;
  let backoffMs = 500;

  const setStatus = (s: WsStatus): void => {
    handlers.onStatus?.(s);
  };

  const connect = (): void => {
    if (stopped) return;
    setStatus("connecting");
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${window.location.host}/api/ws/flows`;
    socket = new WebSocket(url);

    socket.onopen = (): void => {
      backoffMs = 500;
      setStatus("open");
    };
    socket.onmessage = (ev): void => {
      try {
        const flow = JSON.parse(ev.data as string) as Flow;
        handlers.onFlow(flow);
      } catch {
        // ignore malformed message
      }
    };
    socket.onclose = (): void => {
      if (stopped) return;
      setStatus("reconnecting");
      const wait = backoffMs;
      backoffMs = Math.min(backoffMs * 2, 8000);
      setTimeout(connect, wait);
    };
    socket.onerror = (): void => {
      socket?.close();
    };
  };

  connect();
  return (): void => {
    stopped = true;
    socket?.close();
  };
}
