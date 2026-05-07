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
import { DEFAULT_FILTERS, type FlowFilters } from "./types";
import type { ThemeMode } from "./theme";
import { flowMatches } from "./util/filterFlow";
import {
  KeybindingsProvider,
  type Handlers,
} from "./keybindings/KeybindingsProvider";
import { WhichKeyPopup } from "./keybindings/WhichKeyPopup";
import { HintMode } from "./keybindings/HintMode";
import { HelpOverlay } from "./keybindings/HelpOverlay";
import { StatusChip } from "./keybindings/StatusChip";
import { KbHandlersBridge } from "./keybindings/KbHandlersBridge";
import type { Scope } from "./keybindings/registry";

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

  const connections = useMemo(() => {
    const set = new Set<string>();
    for (const f of flows) set.add(f.connection_name);
    return Array.from(set).sort();
  }, [flows]);

  const visible = useMemo(
    () => flowsThroughFilters(flows, filters, nowUs),
    [flows, filters, nowUs],
  );

  const selectedFlow = useMemo(
    () =>
      selectedId == null ? undefined : flows.find((f) => f.id === selectedId),
    [flows, selectedId],
  );

  // ── Keybinding scopes ─────────────────────────────────────────────
  // The set of active scopes drives which scoped bindings fire. Driven
  // by view state + drawer-open state.
  const scopes = useMemo<Scope[]>(() => {
    const out: Scope[] = [];
    if (view === "flows") out.push("table");
    if (view === "tap") out.push("livetap");
    if (selectedId != null) out.push("drawer");
    return out;
  }, [view, selectedId]);

  // ── Handler glue ──────────────────────────────────────────────────
  // Each registry id maps to a setState call (or a side effect like a
  // clipboard write). Keep these one-liners; if a handler grows past a
  // few lines, lift it out into its own function.
  const handlers = useMemo<Handlers>(() => {
    const moveSelection = (delta: number) => {
      if (visible.length === 0) return;
      const idx = visible.findIndex((f) => f.id === selectedId);
      const next =
        idx < 0
          ? delta > 0
            ? 0
            : visible.length - 1
          : Math.min(visible.length - 1, Math.max(0, idx + delta));
      setSelectedId(visible[next]?.id ?? null);
    };
    const yank = (text: string) => {
      void navigator.clipboard.writeText(text);
    };
    return {
      "nav.down": () => moveSelection(1),
      "nav.up": () => moveSelection(-1),
      "nav.top": () => setSelectedId(visible[0]?.id ?? null),
      "nav.bottom": () =>
        setSelectedId(visible[visible.length - 1]?.id ?? null),
      "nav.halfDown": () => moveSelection(10),
      "nav.halfUp": () => moveSelection(-10),
      "flow.open": () => {
        if (selectedId == null && visible[0]) setSelectedId(visible[0].id);
      },
      "flow.close": () => setSelectedId(null),
      "flow.next": () => moveSelection(1),
      "flow.prev": () => moveSelection(-1),
      "goto.table": () => setView("flows"),
      "goto.livetap": () => setView("tap"),
      "goto.filter": () => searchInputRef.current?.focus(),
      "goto.settings": () => setSettingsOpen(true),
      "goto.drawer": () => {
        if (selectedId == null && visible[0]) setSelectedId(visible[0].id);
      },
      "filter.focus": () => searchInputRef.current?.focus(),
      "filter.clear": () => setFilters(DEFAULT_FILTERS),
      "filter.refresh": () => refetch(),
      "ui.toggleDark": () =>
        onThemeModeChange(themeMode === "dark" ? "light" : "dark"),
      "yank.id": () => {
        if (selectedFlow) yank(String(selectedFlow.id));
      },
      "yank.host": () => {
        if (selectedFlow)
          yank(selectedFlow.dst_host ?? selectedFlow.dst_ip);
      },
      "yank.curl": () => {
        if (!selectedFlow) return;
        const target =
          selectedFlow.dst_host ??
          (selectedFlow.dst_ip.includes(":")
            ? `[${selectedFlow.dst_ip}]`
            : selectedFlow.dst_ip);
        yank(`curl https://${target}:${selectedFlow.dst_port}/`);
      },
      "esc.hierarchy": () => {
        if (settingsOpen) {
          setSettingsOpen(false);
          return;
        }
        if (selectedId != null) {
          setSelectedId(null);
          return;
        }
        // Final fallback: clear filters when there's nothing else to dismiss.
      },
    };
  }, [
    visible,
    selectedId,
    selectedFlow,
    settingsOpen,
    refetch,
    themeMode,
    onThemeModeChange,
  ]);

  return (
    <KeybindingsProvider handlers={handlers} scopes={scopes}>
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
        {/* Bridge for `f` → enter hint mode + `?` → toggle help overlay. */}
        <KbHandlersBridge />
        <WhichKeyPopup />
        <HintMode />
        <HelpOverlay />
        <StatusChip />
      </AppShell>
    </KeybindingsProvider>
  );
}

function flowsThroughFilters(
  flows: ReturnType<typeof useLiveFlows>["flows"],
  filters: FlowFilters,
  nowUs: number,
) {
  return flows.filter((f) => flowMatches(f, filters, nowUs));
}
