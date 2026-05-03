import type { Flow } from "../types";

export type FlowEventHandler = (flow: Flow) => void;

/**
 * Connect to the daemon's flow event stream. Auto-reconnects with
 * exponential-ish backoff. Returns a cleanup function.
 */
export function subscribeFlows(handler: FlowEventHandler): () => void {
  let socket: WebSocket | null = null;
  let stopped = false;
  let backoffMs = 500;

  const connect = () => {
    if (stopped) return;
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${window.location.host}/api/ws/flows`;
    socket = new WebSocket(url);

    socket.onopen = () => {
      backoffMs = 500;
    };
    socket.onmessage = (ev) => {
      try {
        const flow = JSON.parse(ev.data) as Flow;
        handler(flow);
      } catch {
        // ignore bad message
      }
    };
    socket.onclose = () => {
      if (stopped) return;
      const wait = backoffMs;
      backoffMs = Math.min(backoffMs * 2, 8000);
      setTimeout(connect, wait);
    };
    socket.onerror = () => {
      socket?.close();
    };
  };

  connect();
  return () => {
    stopped = true;
    socket?.close();
  };
}
