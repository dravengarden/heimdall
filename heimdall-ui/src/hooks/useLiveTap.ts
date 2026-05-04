import { useEffect, useState } from "react";
import type { Message } from "../types";
import { fetchTapMessages } from "../api/client";

/** Cap on the in-memory ring so a busy host doesn't OOM the browser. */
const MAX_KEEP = 1000;

interface State {
  msgs: readonly Message[];
  err: string | null;
  loading: boolean;
}

interface Options {
  /** Polling interval in ms. Defaults to 1000. */
  intervalMs?: number;
  /** When set, only fetch messages for this cgroup_id. */
  cgroupId?: number | null;
}

/**
 * Poll `/api/messages` and accumulate new rows. Only fetches messages
 * with `id > seenMaxId` after the first response, so each tick is
 * an incremental delta.
 *
 * Why polling instead of a WebSocket? The flow API already has a WS
 * endpoint for finished flows; messages are higher-frequency (one
 * SSL_write = one event), and a simple bounded poll keeps the daemon
 * side trivial. We can swap in a WS later if push becomes the bottleneck.
 */
export function useLiveTap(opts: Options = {}): State & {
  clear: () => void;
  paused: boolean;
  setPaused: (p: boolean) => void;
} {
  const { intervalMs = 1000, cgroupId = null } = opts;
  const [msgs, setMsgs] = useState<readonly Message[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;

    // Track the wire-clock floor so each tick only asks for newer rows.
    // We use ts_us+1 rather than id since the backend orders messages
    // ASC by ts_us; that gives us a stable cursor across restarts.
    let cursorUs = 0;

    async function tick(): Promise<void> {
      if (cancelled || paused) return;
      try {
        const params: { limit: number; sinceUs?: number; cgroupId?: number } = {
          limit: 200,
        };
        if (cursorUs > 0) params.sinceUs = cursorUs;
        if (cgroupId != null) params.cgroupId = cgroupId;
        const rows = await fetchTapMessages(params);
        if (cancelled) return;
        if (rows.length > 0) {
          // Drop rows we've already seen (since_us is inclusive on the
          // backend, so the cursor row itself can repeat).
          const fresh = cursorUs > 0
            ? rows.filter((r) => r.ts_us > cursorUs - 1 && true)
            : rows;
          if (fresh.length > 0) {
            cursorUs = Math.max(...fresh.map((r) => r.ts_us)) + 1;
            setMsgs((prev) => {
              const merged = prev.concat(fresh);
              return merged.length > MAX_KEEP
                ? merged.slice(merged.length - MAX_KEEP)
                : merged;
            });
          }
        }
        setErr(null);
        setLoading(false);
      } catch (e: unknown) {
        if (!cancelled) {
          setErr(String(e));
          setLoading(false);
        }
      }
      if (!cancelled) {
        timer = setTimeout(tick, intervalMs);
      }
    }

    void tick();
    return () => {
      cancelled = true;
      if (timer != null) clearTimeout(timer);
    };
  }, [intervalMs, cgroupId, paused]);

  return {
    msgs,
    err,
    loading,
    paused,
    setPaused,
    clear: () => setMsgs([]),
  };
}
