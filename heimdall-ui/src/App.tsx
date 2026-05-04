import { useEffect, useMemo, useRef, useState } from "react";
import { Box } from "@mui/material";
import { AppShell, type AppView } from "./components/AppShell";
import { FilterBar } from "./components/FilterBar";
import { ActiveFilterChips } from "./components/ActiveFilterChips";
import { FlowTable } from "./components/FlowTable";
import { FlowDetail } from "./components/FlowDetail";
import { LiveTapView } from "./components/LiveTapView";
import { SettingsDrawer } from "./components/SettingsDrawer";
import { useLiveFlows } from "./hooks/useLiveFlows";
import { useKeyboardShortcuts } from "./hooks/useKeyboardShortcuts";
import { DEFAULT_FILTERS, type FlowFilters } from "./types";
import type { ThemeMode } from "./theme";
import { flowMatches } from "./util/filterFlow";

interface Props {
  themeMode: ThemeMode;
  onThemeModeChange: (m: ThemeMode) => void;
  fontSize: number;
  onFontSizeChange: (px: number) => void;
}

export function App({
  themeMode,
  onThemeModeChange,
  fontSize,
  onFontSizeChange,
}: Props) {
  const { flows, refetch, wsStatus } = useLiveFlows(300);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [view, setView] = useState<AppView>("flows");
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  const [filters, setFilters] = useState<FlowFilters>(DEFAULT_FILTERS);

  // `ageMaxSec` filter must use a "now" that ticks; without this, an aged-out
  // row would stay visible until something else triggers a re-render.
  const [nowUs, setNowUs] = useState<number>(Date.now() * 1000);
  useEffect(() => {
    if (filters.ageMaxSec == null) return;
    const id = setInterval(() => setNowUs(Date.now() * 1000), 1000);
    return () => clearInterval(id);
  }, [filters.ageMaxSec]);

  useKeyboardShortcuts({ searchInputRef, selectedId, setSelectedId });

  const connections = useMemo(() => {
    const set = new Set<string>();
    for (const f of flows) set.add(f.connection_name);
    return Array.from(set).sort();
  }, [flows]);

  const visible = useMemo(
    () => flows.filter((f) => flowMatches(f, filters, nowUs)),
    [flows, filters, nowUs],
  );

  const selectedFlow = useMemo(
    () =>
      selectedId == null ? undefined : flows.find((f) => f.id === selectedId),
    [flows, selectedId],
  );

  return (
    <AppShell
      view={view}
      onViewChange={setView}
      onOpenSettings={() => setSettingsOpen(true)}
    >
      {view === "flows" ? (
        <>
          <FilterBar
            filters={filters}
            onChange={setFilters}
            total={flows.length}
            visible={visible.length}
            onRefresh={refetch}
            connections={connections}
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
        </>
      ) : (
        <LiveTapView />
      )}
      <SettingsDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        mode={themeMode}
        onModeChange={onThemeModeChange}
        fontSize={fontSize}
        onFontSizeChange={onFontSizeChange}
      />
    </AppShell>
  );
}
