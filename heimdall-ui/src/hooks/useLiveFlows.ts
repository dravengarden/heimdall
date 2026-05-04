import { useCallback, useEffect, useState } from "react";
import type { Flow } from "../types";
import { fetchFlows } from "../api/client";
import { subscribeFlows, type WsStatus } from "../api/ws";

/// In-memory cache cap. Beyond this, the oldest flows are evicted.
/// DataGrid still renders only one page (100 by default), so this is
/// effectively the lookback window the user can scroll through
/// without round-tripping to the backend. The full history is in
/// sqlite — `heimdall flows list` and the HTTP API can replay
/// anything that aged out of the cache.
const MAX_FLOWS = 3000;

export interface UseLiveFlows {
  flows: readonly Flow[];
  loading: boolean;
  refetch: () => void;
  wsStatus: WsStatus;
}

/**
 * Initial fetch of the latest flows + WebSocket subscription that
 * prepends new flows to the list, capped at `MAX_FLOWS`.
 *
 * No pause control — flows are persisted to sqlite by the daemon
 * regardless of UI state, and freezing a row in place isn't useful
 * once the detail drawer is open (selecting a flow there pins it
 * independently of the live list).
 */
export function useLiveFlows(initialLimit = 200): UseLiveFlows {
  const [flows, setFlows] = useState<readonly Flow[]>([]);
  const [loading, setLoading] = useState(true);
  const [wsStatus, setWsStatus] = useState<WsStatus>("connecting");

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
        setFlows((prev) => {
          // De-dupe by id; insert newest at front. FIFO eviction
          // when over the cap so memory stays bounded.
          const filtered = prev.filter((f) => f.id !== flow.id);
          const next = [flow, ...filtered];
          return next.length > MAX_FLOWS ? next.slice(0, MAX_FLOWS) : next;
        });
      },
      onStatus: setWsStatus,
    });
    return cleanup;
  }, []);

  return { flows, loading, refetch, wsStatus };
}
