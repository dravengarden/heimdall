import type { ReactNode } from "react";
import {
  AppBar,
  Box,
  Chip,
  IconButton,
  Stack,
  Toolbar,
  Tooltip,
  Typography,
} from "@mui/material";
import ShieldOutlinedIcon from "@mui/icons-material/ShieldOutlined";
import GitHubIcon from "@mui/icons-material/GitHub";
import LinkIcon from "@mui/icons-material/Link";
import SettingsIcon from "@mui/icons-material/SettingsOutlined";
import { useStatus } from "../hooks/useStatus";
import { useI18n } from "../i18n";

interface Props {
  children: ReactNode;
  onOpenSettings: () => void;
}

export function AppShell({ children, onOpenSettings }: Props) {
  const status = useStatus();
  const { t } = useI18n();

  return (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100vh" }}>
      <AppBar position="sticky">
        <Toolbar variant="dense" sx={{ gap: 2 }}>
          <ShieldOutlinedIcon color="primary" />
          <Typography variant="h6" sx={{ flex: 0 }}>
            {t("app.title")}
          </Typography>
          {status && (
            <Stack direction="row" spacing={1} alignItems="center">
              <Chip
                size="small"
                label={`v${status.version}`}
                color="primary"
                variant="outlined"
              />
              <Tooltip title="Default connection">
                <Chip
                  size="small"
                  icon={<LinkIcon />}
                  label={status.default_connection}
                  color="success"
                  variant="outlined"
                />
              </Tooltip>
              <Tooltip title="Relay listen">
                <Chip
                  size="small"
                  label={status.relay_listen}
                  variant="outlined"
                  sx={{ fontFamily: "ui-monospace, monospace" }}
                />
              </Tooltip>
              <Tooltip title="Fake-IP DNS">
                <Chip
                  size="small"
                  label={`DNS ${status.dns_listen} → ${status.fake_ip_cidr}`}
                  variant="outlined"
                  sx={{ fontFamily: "ui-monospace, monospace" }}
                />
              </Tooltip>
            </Stack>
          )}
          <Box sx={{ flex: 1 }} />
          <Tooltip title={t("settings.title")}>
            <IconButton size="small" onClick={onOpenSettings} aria-label="settings">
              <SettingsIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="GitHub">
            <a
              href="https://github.com/dravengarden/heimdall"
              target="_blank"
              rel="noreferrer"
              style={{ color: "inherit", display: "inline-flex" }}
            >
              <GitHubIcon fontSize="small" />
            </a>
          </Tooltip>
        </Toolbar>
      </AppBar>
      <Box
        component="main"
        sx={{
          flex: 1,
          minHeight: 0,
          display: "flex",
          flexDirection: "column",
          overflow: "hidden",
        }}
      >
        {children}
      </Box>
    </Box>
  );
}
