import { useEffect, useState } from "react";
import type { Status } from "../types";
import { fetchStatus } from "../api/client";

export function useStatus(pollMs = 5000): Status | null {
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      try {
        const s = await fetchStatus();
        if (!cancelled) setStatus(s);
      } catch {
        // swallow; the poller will retry on next tick
      }
    };
    void run();
    const timer = setInterval(() => void run(), pollMs);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [pollMs]);

  return status;
}
