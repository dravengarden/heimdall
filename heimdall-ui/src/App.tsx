import { useMemo, useRef, useState } from "react";
import { Box } from "@mui/material";
import { AppShell } from "./components/AppShell";
import { FilterBar } from "./components/FilterBar";
import { ActiveFilterChips } from "./components/ActiveFilterChips";
import { FlowTable } from "./components/FlowTable";
import { FlowDetail } from "./components/FlowDetail";
import { useLiveFlows } from "./hooks/useLiveFlows";
import { useKeyboardShortcuts } from "./hooks/useKeyboardShortcuts";
import type { FlowFilters } from "./types";

export function App() {
  const { flows, paused, setPaused, refetch, wsStatus } = useLiveFlows(300);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  const [filters, setFilters] = useState<FlowFilters>({
    query: "",
    connection: null,
    hideErrors: false,
  });

  useKeyboardShortcuts({ searchInputRef, selectedId, setSelectedId });

  const connections = useMemo(() => {
    const set = new Set<string>();
    for (const f of flows) set.add(f.connection_name);
    return Array.from(set).sort();
  }, [flows]);

  const visible = useMemo(() => {
    const q = filters.query.trim().toLowerCase();
    return flows.filter((f) => {
      if (filters.hideErrors && f.error) return false;
      if (filters.connection && f.connection_name !== filters.connection)
        return false;
      if (q.length === 0) return true;
      const fields: ReadonlyArray<string | null> = [
        f.dst_host,
        f.dst_ip,
        f.pod_name,
        f.namespace,
        f.connection_name,
        f.upstream_addr,
      ];
      return fields.some((s) => s != null && s.toLowerCase().includes(q));
    });
  }, [flows, filters]);

  const selectedFlow = useMemo(
    () => (selectedId == null ? undefined : flows.find((f) => f.id === selectedId)),
    [flows, selectedId],
  );

  return (
    <AppShell>
      <FilterBar
        filters={filters}
        onChange={setFilters}
        total={flows.length}
        visible={visible.length}
        paused={paused}
        onTogglePause={() => setPaused(!paused)}
        onRefresh={refetch}
        connections={connections}
        visibleFlows={visible}
        wsStatus={wsStatus}
        searchInputRef={searchInputRef}
      />
      <ActiveFilterChips filters={filters} onChange={setFilters} />
      <Box sx={{ flex: 1, minHeight: 0 }}>
        <FlowTable
          flows={visible}
          selectedId={selectedId}
          onSelect={setSelectedId}
        />
      </Box>
      <FlowDetail
        flowId={selectedId}
        onClose={() => setSelectedId(null)}
        fallback={selectedFlow}
      />
    </AppShell>
  );
}
