import { Box, Chip, Typography } from "@mui/material";
import type { FlowFilters } from "../types";

interface Props {
  filters: FlowFilters;
  onChange: (filters: FlowFilters) => void;
}

export function ActiveFilterChips({ filters, onChange }: Props) {
  const chips: { key: string; label: string; clear: () => void }[] = [];

  if (filters.query.trim().length > 0) {
    chips.push({
      key: "q",
      label: `query: "${filters.query.trim()}"`,
      clear: () => onChange({ ...filters, query: "" }),
    });
  }
  if (filters.connection) {
    chips.push({
      key: "conn",
      label: `conn = ${filters.connection}`,
      clear: () => onChange({ ...filters, connection: null }),
    });
  }
  if (filters.hideErrors) {
    chips.push({
      key: "hide",
      label: "hide errors",
      clear: () => onChange({ ...filters, hideErrors: false }),
    });
  }

  if (chips.length === 0) return null;

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
        background: (t) => t.palette.background.paper,
      }}
    >
      <Typography
        variant="caption"
        color="text.secondary"
        sx={{ alignSelf: "center", letterSpacing: 0.4, textTransform: "uppercase" }}
      >
        filters
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
        label="clear all"
        variant="filled"
        onClick={() =>
          onChange({ query: "", connection: null, hideErrors: false })
        }
        sx={{ ml: 0.5 }}
      />
    </Box>
  );
}
