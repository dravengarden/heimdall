import {
  Box,
  Chip,
  Divider,
  Popover,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import type { FlowFilters } from "../types";
import { useI18n } from "../i18n";

interface Props {
  anchorEl: HTMLElement | null;
  onClose: () => void;
  filters: FlowFilters;
  onChange: (f: FlowFilters) => void;
}

const AGE_PRESETS: ReadonlyArray<{ secs: number | null; key: string }> = [
  { secs: null, key: "filter.adv.ageNone" },
  { secs: 60, key: "filter.adv.age1m" },
  { secs: 5 * 60, key: "filter.adv.age5m" },
  { secs: 15 * 60, key: "filter.adv.age15m" },
  { secs: 60 * 60, key: "filter.adv.age1h" },
  { secs: 24 * 60 * 60, key: "filter.adv.age24h" },
];

export function AdvancedFiltersPopover({
  anchorEl,
  onClose,
  filters,
  onChange,
}: Props) {
  const { t } = useI18n();

  const updPort = (key: "portMin" | "portMax", v: string): void => {
    const n = v.trim() === "" ? null : Number(v);
    onChange({ ...filters, [key]: Number.isFinite(n) ? n : null });
  };

  const updBytes = (v: string): void => {
    const n = v.trim() === "" ? null : Number(v);
    onChange({ ...filters, bytesMin: Number.isFinite(n) ? n : null });
  };

  const reset = (): void =>
    onChange({
      ...filters,
      portMin: null,
      portMax: null,
      bytesMin: null,
      ageMaxSec: null,
    });

  return (
    <Popover
      open={anchorEl != null}
      anchorEl={anchorEl}
      onClose={onClose}
      anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      transformOrigin={{ vertical: "top", horizontal: "right" }}
      slotProps={{
        paper: {
          sx: { width: 360, p: 2 },
        },
      }}
    >
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1.5 }}>
        <Typography variant="subtitle2">{t("filter.adv.title")}</Typography>
        <Box sx={{ flex: 1 }} />
        <Chip
          size="small"
          label={t("filter.adv.reset")}
          variant="outlined"
          onClick={reset}
        />
      </Stack>
      <Divider sx={{ mb: 1.5 }} />

      <Stack spacing={2}>
        {/* Port range */}
        <Box>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: "block", mb: 0.5 }}
          >
            {t("filter.adv.portRange")}
          </Typography>
          <Stack direction="row" spacing={1}>
            <TextField
              size="small"
              type="number"
              placeholder={t("filter.adv.portMin")}
              value={filters.portMin ?? ""}
              onChange={(e) => updPort("portMin", e.target.value)}
              slotProps={{ htmlInput: { min: 0, max: 65535 } }}
              sx={{ flex: 1 }}
            />
            <TextField
              size="small"
              type="number"
              placeholder={t("filter.adv.portMax")}
              value={filters.portMax ?? ""}
              onChange={(e) => updPort("portMax", e.target.value)}
              slotProps={{ htmlInput: { min: 0, max: 65535 } }}
              sx={{ flex: 1 }}
            />
          </Stack>
        </Box>

        {/* Min bytes */}
        <Box>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: "block", mb: 0.5 }}
          >
            {t("filter.adv.bytesMin")}
          </Typography>
          <TextField
            size="small"
            fullWidth
            type="number"
            placeholder="0"
            value={filters.bytesMin ?? ""}
            onChange={(e) => updBytes(e.target.value)}
            slotProps={{ htmlInput: { min: 0 } }}
          />
        </Box>

        {/* Age */}
        <Box>
          <Typography
            variant="caption"
            color="text.secondary"
            sx={{ display: "block", mb: 0.5 }}
          >
            {t("filter.adv.age")}
          </Typography>
          <ToggleButtonGroup
            exclusive
            size="small"
            value={filters.ageMaxSec ?? "all"}
            onChange={(_, v: number | "all" | null) => {
              if (v === null) return;
              onChange({
                ...filters,
                ageMaxSec: v === "all" ? null : (v as number),
              });
            }}
            sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}
          >
            {AGE_PRESETS.map((p) => (
              <ToggleButton
                key={p.key}
                value={p.secs ?? "all"}
                sx={{ flex: "0 0 auto", textTransform: "none", py: 0.25 }}
              >
                {t(p.key)}
              </ToggleButton>
            ))}
          </ToggleButtonGroup>
        </Box>
      </Stack>
    </Popover>
  );
}
