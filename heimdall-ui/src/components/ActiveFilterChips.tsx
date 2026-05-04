import { Box, Chip, Typography } from "@mui/material";
import type { FlowFilters } from "../types";
import { DEFAULT_FILTERS } from "../types";
import { useI18n } from "../i18n";
import { isFiltered } from "../util/filterFlow";

interface Props {
  filters: FlowFilters;
  onChange: (filters: FlowFilters) => void;
}

export function ActiveFilterChips({ filters, onChange }: Props) {
  const { t } = useI18n();
  if (!isFiltered(filters)) return null;

  const chips: { key: string; label: string; clear: () => void }[] = [];

  if (filters.query.trim().length > 0) {
    chips.push({
      key: "q",
      label: filters.query.trim(),
      clear: () => onChange({ ...filters, query: "" }),
    });
  }

  if (filters.connections.length > 0) {
    const value = filters.connections.join(", ");
    chips.push({
      key: "conns",
      label: `${t("filter.adv.connsLabel")} {${value}}`,
      clear: () => onChange({ ...filters, connections: [] }),
    });
  }

  if (filters.errorMode === "ok") {
    chips.push({
      key: "err",
      label: t("filter.hideErrors"),
      clear: () => onChange({ ...filters, errorMode: "all" }),
    });
  } else if (filters.errorMode === "errors-only") {
    chips.push({
      key: "err",
      label: t("filter.errorsOnly"),
      clear: () => onChange({ ...filters, errorMode: "all" }),
    });
  }

  if (filters.portMin != null || filters.portMax != null) {
    const label = portRangeLabel(filters.portMin, filters.portMax);
    chips.push({
      key: "port",
      label: `${t("filter.adv.portLabel")} ${label}`,
      clear: () => onChange({ ...filters, portMin: null, portMax: null }),
    });
  }

  if (filters.bytesMin != null) {
    chips.push({
      key: "bytes",
      label: `${t("filter.adv.bytesLabel")} ${humanBytes(filters.bytesMin)}`,
      clear: () => onChange({ ...filters, bytesMin: null }),
    });
  }

  if (filters.ageMaxSec != null) {
    chips.push({
      key: "age",
      label: `${t("filter.adv.ageLabel")} ${humanAge(filters.ageMaxSec)}`,
      clear: () => onChange({ ...filters, ageMaxSec: null }),
    });
  }

  return (
    <Box
      sx={{
        display: "flex",
        flexWrap: "wrap",
        gap: 0.75,
        px: 2,
        py: 0.75,
        borderBottom: 1,
        borderColor: "divider",
        background: (theme) => theme.palette.background.paper,
      }}
    >
      <Typography
        variant="caption"
        color="text.secondary"
        sx={{
          alignSelf: "center",
          letterSpacing: 0.4,
          textTransform: "uppercase",
        }}
      >
        {t("filter.filtersLabel")}
      </Typography>
      {chips.map((c) => (
        <Chip
          key={c.key}
          size="small"
          label={c.label}
          onDelete={c.clear}
          variant="outlined"
        />
      ))}
      <Chip
        size="small"
        label={t("filter.clearAll")}
        variant="filled"
        onClick={() => onChange(DEFAULT_FILTERS)}
        sx={{ ml: 0.5 }}
      />
    </Box>
  );
}

function portRangeLabel(min: number | null, max: number | null): string {
  if (min != null && max != null) return min === max ? `${min}` : `${min}–${max}`;
  if (min != null) return `≥${min}`;
  if (max != null) return `≤${max}`;
  return "";
}

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function humanAge(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h`;
  return `${Math.round(secs / 86400)}d`;
}
