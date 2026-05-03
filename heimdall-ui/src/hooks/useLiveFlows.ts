import { useCallback, useEffect, useRef, useState } from "react";
import type { Flow } from "../types";
import { fetchFlows } from "../api/client";
import { subscribeFlows, type WsStatus } from "../api/ws";

const MAX_FLOWS = 1000;

export interface UseLiveFlows {
  flows: readonly Flow[];
  loading: boolean;
  paused: boolean;
  setPaused: (paused: boolean) => void;
  refetch: () => void;
  wsStatus: WsStatus;
}

/**
 * Initial fetch of the latest flows + WebSocket subscription that
 * prepends new flows to the list. Caps the in-memory list at
 * `MAX_FLOWS` to keep the UI responsive.
 */
export function useLiveFlows(initialLimit = 200): UseLiveFlows {
  const [flows, setFlows] = useState<readonly Flow[]>([]);
  const [loading, setLoading] = useState(true);
  const [paused, setPaused] = useState(false);
  const [wsStatus, setWsStatus] = useState<WsStatus>("connecting");
  const pausedRef = useRef(paused);
  pausedRef.current = paused;

  const refetch = useCallback((): void => {
    setLoading(true);
    fetchFlows({ limit: initialLimit })
      .then((rows) => setFlows(rows))
      .catch(() => {
        /* keep stale data */
      })
      .finally(() => setLoading(false));
  }, [initialLimit]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  useEffect(() => {
    const cleanup = subscribeFlows({
      onFlow: (flow) => {
        if (pausedRef.current) return;
        setFlows((prev) => {
          // De-dupe by id; insert newest at front.
          const filtered = prev.filter((f) => f.id !== flow.id);
          const next = [flow, ...filtered];
          return next.length > MAX_FLOWS ? next.slice(0, MAX_FLOWS) : next;
        });
      },
      onStatus: setWsStatus,
    });
    return cleanup;
  }, []);

  return { flows, loading, paused, setPaused, refetch, wsStatus };
}
