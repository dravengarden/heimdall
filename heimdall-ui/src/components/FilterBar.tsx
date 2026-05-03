import { useId } from "react";
import {
  Box,
  Chip,
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
import type { FlowFilters } from "../types";

interface Props {
  filters: FlowFilters;
  onChange: (filters: FlowFilters) => void;
  total: number;
  visible: number;
  paused: boolean;
  onTogglePause: () => void;
  onRefresh: () => void;
  connections: readonly string[];
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
}: Props) {
  const searchId = useId();

  return (
    <Box
      sx={{
        display: "flex",
        gap: 1.5,
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
        placeholder="filter by host / pod / IP / connection…"
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
        onChange={(_, v: string | null) =>
          onChange({ ...filters, hideErrors: v === "ok" })
        }
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
        <Tooltip title={paused ? "Resume live updates" : "Pause live updates"}>
          <IconButton size="small" onClick={onTogglePause}>
            {paused ? (
              <PlayArrowIcon fontSize="small" color="warning" />
            ) : (
              <PauseIcon fontSize="small" />
            )}
          </IconButton>
        </Tooltip>
        <Tooltip title="Refetch">
          <IconButton size="small" onClick={onRefresh}>
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Stack>
    </Box>
  );
}
