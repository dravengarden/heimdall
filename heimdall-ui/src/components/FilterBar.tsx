import { useId } from "react";
import {
  Box,
  Chip,
  Divider,
  IconButton,
  InputAdornment,
  MenuItem,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import ClearIcon from "@mui/icons-material/Clear";
import PauseIcon from "@mui/icons-material/PauseCircleOutline";
import PlayArrowIcon from "@mui/icons-material/PlayCircleOutline";
import RefreshIcon from "@mui/icons-material/Refresh";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutline";
import DownloadIcon from "@mui/icons-material/FileDownload";
import type { FlowFilters, Flow } from "../types";
import { downloadJson } from "../util/clipboard";
import { WsStatusBadge } from "./WsStatusBadge";
import type { WsStatus } from "../api/ws";

interface Props {
  filters: FlowFilters;
  onChange: (filters: FlowFilters) => void;
  total: number;
  visible: number;
  paused: boolean;
  onTogglePause: () => void;
  onRefresh: () => void;
  connections: readonly string[];
  visibleFlows: readonly Flow[];
  wsStatus: WsStatus;
  searchInputRef: React.Ref<HTMLInputElement>;
}

export function FilterBar({
  filters,
  onChange,
  total,
  visible,
  paused,
  onTogglePause,
  onRefresh,
  connections,
  visibleFlows,
  wsStatus,
  searchInputRef,
}: Props) {
  const searchId = useId();

  const exportJson = (): void => {
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, -5);
    downloadJson(`heimdall-flows-${ts}.json`, visibleFlows);
  };

  return (
    <Box
      sx={{
        display: "flex",
        gap: 1.25,
        alignItems: "center",
        px: 2,
        py: 1,
        borderBottom: 1,
        borderColor: "divider",
        background: (t) => t.palette.background.paper,
      }}
    >
      <TextField
        id={searchId}
        inputRef={searchInputRef}
        placeholder="filter by host / pod / IP / connection…  (press /)"
        size="small"
        variant="outlined"
        value={filters.query}
        onChange={(e) => onChange({ ...filters, query: e.target.value })}
        sx={{ flex: 1, maxWidth: 480 }}
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
            endAdornment: filters.query ? (
              <InputAdornment position="end">
                <IconButton
                  size="small"
                  onClick={() => onChange({ ...filters, query: "" })}
                  aria-label="clear search"
                >
                  <ClearIcon fontSize="small" />
                </IconButton>
              </InputAdornment>
            ) : null,
          },
        }}
      />

      <TextField
        select
        size="small"
        variant="outlined"
        value={filters.connection ?? ""}
        onChange={(e) =>
          onChange({
            ...filters,
            connection: e.target.value === "" ? null : e.target.value,
          })
        }
        sx={{ minWidth: 160 }}
      >
        <MenuItem value="">all connections</MenuItem>
        {connections.map((c) => (
          <MenuItem key={c} value={c}>
            {c}
          </MenuItem>
        ))}
      </TextField>

      <ToggleButtonGroup
        size="small"
        exclusive
        value={filters.hideErrors ? "ok" : "all"}
        onChange={(_, v: string | null) => {
          if (v == null) return;
          onChange({ ...filters, hideErrors: v === "ok" });
        }}
      >
        <ToggleButton value="all">all</ToggleButton>
        <ToggleButton value="ok">
          <Tooltip title="Hide flows with errors">
            <ErrorOutlineIcon fontSize="small" />
          </Tooltip>
        </ToggleButton>
      </ToggleButtonGroup>

      <Stack direction="row" spacing={1} alignItems="center" sx={{ ml: "auto" }}>
        <Chip
          size="small"
          label={`${visible} / ${total}`}
          variant="outlined"
          sx={{ fontFamily: "ui-monospace, monospace" }}
        />
        <Divider orientation="vertical" flexItem sx={{ mx: 0.5, my: 0.5 }} />
        <WsStatusBadge status={wsStatus} />
        <Tooltip title={paused ? "Resume live updates" : "Pause live updates"}>
          <IconButton size="small" onClick={onTogglePause} aria-label="pause">
            {paused ? (
              <PlayArrowIcon fontSize="small" color="warning" />
            ) : (
              <PauseIcon fontSize="small" />
            )}
          </IconButton>
        </Tooltip>
        <Tooltip title="Refetch">
          <IconButton size="small" onClick={onRefresh} aria-label="refresh">
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Tooltip>
        <Tooltip title="Download visible flows as JSON">
          <span>
            <IconButton
              size="small"
              onClick={exportJson}
              disabled={visibleFlows.length === 0}
              aria-label="export"
            >
              <DownloadIcon fontSize="small" />
            </IconButton>
          </span>
        </Tooltip>
      </Stack>
    </Box>
  );
}
