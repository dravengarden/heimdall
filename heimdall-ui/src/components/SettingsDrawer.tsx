import {
  Box,
  Drawer,
  IconButton,
  MenuItem,
  Slider,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import LightModeIcon from "@mui/icons-material/LightMode";
import DarkModeIcon from "@mui/icons-material/DarkMode";
import SettingsBrightnessIcon from "@mui/icons-material/SettingsBrightness";
import { useI18n, type Locale } from "../i18n";
import type { ThemeMode } from "../theme";
import { FONT_SIZE_BOUNDS } from "../hooks/useThemeMode";

interface Props {
  open: boolean;
  onClose: () => void;
  mode: ThemeMode;
  onModeChange: (m: ThemeMode) => void;
  fontSize: number;
  onFontSizeChange: (px: number) => void;
}

export function SettingsDrawer({
  open,
  onClose,
  mode,
  onModeChange,
  fontSize,
  onFontSizeChange,
}: Props) {
  const { t, locale, setLocale } = useI18n();

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      slotProps={{
        paper: {
          sx: { width: 360, maxWidth: "90vw" },
        },
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", px: 2, py: 1 }}>
        <Typography variant="h6">{t("settings.title")}</Typography>
        <Box sx={{ flex: 1 }} />
        <IconButton size="small" onClick={onClose} aria-label="close">
          <CloseIcon />
        </IconButton>
      </Box>

      <Box sx={{ px: 2, py: 1, display: "flex", flexDirection: "column", gap: 3 }}>
        <Section title={t("settings.appearance")}>
          <Stack spacing={2}>
            <Box>
              <FieldLabel>{t("settings.theme")}</FieldLabel>
              <ToggleButtonGroup
                exclusive
                size="small"
                fullWidth
                value={mode}
                onChange={(_, v: ThemeMode | null) => v && onModeChange(v)}
              >
                <ToggleButton value="light">
                  <LightModeIcon fontSize="small" />
                  <Box sx={{ ml: 0.75 }}>{t("settings.theme.light")}</Box>
                </ToggleButton>
                <ToggleButton value="dark">
                  <DarkModeIcon fontSize="small" />
                  <Box sx={{ ml: 0.75 }}>{t("settings.theme.dark")}</Box>
                </ToggleButton>
                <ToggleButton value="auto">
                  <SettingsBrightnessIcon fontSize="small" />
                  <Box sx={{ ml: 0.75 }}>{t("settings.theme.auto")}</Box>
                </ToggleButton>
              </ToggleButtonGroup>
            </Box>

            <Box>
              <FieldLabel>
                {t("settings.fontSize")} —{" "}
                <Box component="span" sx={{ fontFamily: "ui-monospace, monospace" }}>
                  {fontSize}px
                </Box>
              </FieldLabel>
              <Slider
                size="small"
                value={fontSize}
                min={FONT_SIZE_BOUNDS.min}
                max={FONT_SIZE_BOUNDS.max}
                step={1}
                marks={[
                  { value: FONT_SIZE_BOUNDS.min, label: `${FONT_SIZE_BOUNDS.min}` },
                  { value: FONT_SIZE_BOUNDS.default, label: `${FONT_SIZE_BOUNDS.default}` },
                  { value: FONT_SIZE_BOUNDS.max, label: `${FONT_SIZE_BOUNDS.max}` },
                ]}
                onChange={(_, v) =>
                  onFontSizeChange(Array.isArray(v) ? (v[0] ?? 13) : v)
                }
                sx={{ mt: 1 }}
              />
            </Box>
          </Stack>
        </Section>

        <Section title={t("settings.language")}>
          <TextField
            select
            size="small"
            fullWidth
            value={locale}
            onChange={(e) => setLocale(e.target.value as Locale)}
          >
            <MenuItem value="en">{t("settings.language.en")}</MenuItem>
            <MenuItem value="zh-CN">{t("settings.language.zh-CN")}</MenuItem>
          </TextField>
        </Section>

        <Section title={t("settings.about")}>
          <Typography variant="body2" color="text.secondary">
            heimdall — transparent SOCKS5 egress + observability
          </Typography>
          <Typography
            variant="caption"
            color="text.disabled"
            sx={{ fontFamily: "ui-monospace, monospace" }}
          >
            github.com/dravengarden/heimdall
          </Typography>
        </Section>
      </Box>
    </Drawer>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <Box>
      <Typography
        variant="overline"
        sx={{
          color: "text.disabled",
          letterSpacing: 0.6,
          display: "block",
          mb: 0.75,
        }}
      >
        {title}
      </Typography>
      {children}
    </Box>
  );
}

function FieldLabel({ children }: { children: React.ReactNode }) {
  return (
    <Typography
      variant="caption"
      sx={{ display: "block", mb: 0.5, color: "text.secondary" }}
    >
      {children}
    </Typography>
  );
}
