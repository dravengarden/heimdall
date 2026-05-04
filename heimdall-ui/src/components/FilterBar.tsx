import { useId, useState } from "react";
import {
  Autocomplete,
  Badge,
  Box,
  Chip,
  Divider,
  IconButton,
  InputAdornment,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  type TextFieldProps,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import ClearIcon from "@mui/icons-material/Clear";
import PauseIcon from "@mui/icons-material/PauseCircleOutline";
import PlayArrowIcon from "@mui/icons-material/PlayCircleOutline";
import RefreshIcon from "@mui/icons-material/Refresh";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutline";
import FilterListOffIcon from "@mui/icons-material/FilterListOff";
import ReportProblemIcon from "@mui/icons-material/ReportProblem";
import DownloadIcon from "@mui/icons-material/FileDownload";
import TuneIcon from "@mui/icons-material/Tune";
import type { Flow, FlowFilters } from "../types";
import { downloadJson } from "../util/clipboard";
import { WsStatusBadge } from "./WsStatusBadge";
import { AdvancedFiltersPopover } from "./AdvancedFiltersPopover";
import type { WsStatus } from "../api/ws";
import { useI18n } from "../i18n";
import { connectionColor } from "../theme";

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
  const { t } = useI18n();
  const [advAnchor, setAdvAnchor] = useState<HTMLElement | null>(null);

  const exportJson = (): void => {
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, -5);
    downloadJson(`heimdall-flows-${ts}.json`, visibleFlows);
  };

  const advFilterCount =
    (filters.portMin != null ? 1 : 0) +
    (filters.portMax != null && filters.portMax !== filters.portMin ? 1 : 0) +
    (filters.bytesMin != null ? 1 : 0) +
    (filters.ageMaxSec != null ? 1 : 0);

  return (
    <>
      <Box
        sx={{
          display: "flex",
          gap: 1.25,
          alignItems: "center",
          px: 2,
          py: 1,
          borderBottom: 1,
          borderColor: "divider",
          background: (theme) => theme.palette.background.paper,
        }}
      >
        <TextField
          id={searchId}
          inputRef={searchInputRef}
          placeholder={t("filter.placeholder")}
          size="small"
          variant="outlined"
          value={filters.query}
          onChange={(e) => onChange({ ...filters, query: e.target.value })}
          sx={{ flex: 1, maxWidth: 420 }}
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

        <Autocomplete
          multiple
          size="small"
          disablePortal={false}
          options={connections as string[]}
          value={filters.connections as string[]}
          onChange={(_, v) => onChange({ ...filters, connections: v })}
          renderTags={(value, getTagProps) =>
            value.map((option, index) => {
              const { key, ...rest } = getTagProps({ index });
              return (
                <Chip
                  key={key}
                  size="small"
                  label={option}
                  color={connectionColor(option)}
                  variant="filled"
                  {...rest}
                />
              );
            })
          }
          renderInput={(params) => (
            // MUI's AutocompleteRenderInputParams declares some inner props
            // as `string | undefined`; under exactOptionalPropertyTypes the
            // spread into TextField doesn't typecheck. Cast through the
            // documented prop type — this is the spread MUI examples show.
            <TextField
              {...(params as unknown as TextFieldProps)}
              size="small"
              placeholder={
                filters.connections.length === 0
                  ? t("filter.allConnections")
                  : ""
              }
            />
          )}
          sx={{ minWidth: 220, maxWidth: 320 }}
        />

        <ToggleButtonGroup
          size="small"
          exclusive
          value={filters.errorMode}
          onChange={(_, v: FlowFilters["errorMode"] | null) => {
            if (v == null) return;
            onChange({ ...filters, errorMode: v });
          }}
        >
          <ToggleButton value="all">
            <Tooltip title={t("filter.all")}>
              <FilterListOffIcon fontSize="small" />
            </Tooltip>
          </ToggleButton>
          <ToggleButton value="ok">
            <Tooltip title={t("filter.hideErrors")}>
              <ErrorOutlineIcon fontSize="small" />
            </Tooltip>
          </ToggleButton>
          <ToggleButton value="errors-only">
            <Tooltip title={t("filter.errorsOnly")}>
              <ReportProblemIcon fontSize="small" color="error" />
            </Tooltip>
          </ToggleButton>
        </ToggleButtonGroup>

        <Tooltip title={t("filter.more")}>
          <IconButton
            size="small"
            onClick={(e) => setAdvAnchor(e.currentTarget)}
            aria-label="more filters"
          >
            <Badge
              color="primary"
              variant={advFilterCount > 0 ? "dot" : "standard"}
            >
              <TuneIcon fontSize="small" />
            </Badge>
          </IconButton>
        </Tooltip>

        <Stack
          direction="row"
          spacing={1}
          alignItems="center"
          sx={{ ml: "auto" }}
        >
          <Chip
            size="small"
            label={`${visible} / ${total}`}
            variant="outlined"
            sx={{ fontFamily: "ui-monospace, monospace" }}
          />
          <Divider orientation="vertical" flexItem sx={{ mx: 0.5, my: 0.5 }} />
          <WsStatusBadge status={wsStatus} />
          <Tooltip title={paused ? t("filter.resume") : t("filter.pause")}>
            <IconButton size="small" onClick={onTogglePause} aria-label="pause">
              {paused ? (
                <PlayArrowIcon fontSize="small" color="warning" />
              ) : (
                <PauseIcon fontSize="small" />
              )}
            </IconButton>
          </Tooltip>
          <Tooltip title={t("filter.refetch")}>
            <IconButton size="small" onClick={onRefresh} aria-label="refresh">
              <RefreshIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title={t("filter.export")}>
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

      <AdvancedFiltersPopover
        anchorEl={advAnchor}
        onClose={() => setAdvAnchor(null)}
        filters={filters}
        onChange={onChange}
      />
    </>
  );
}
