import { Box, Tooltip } from "@mui/material";
import type { WsStatus } from "../api/ws";
import { useI18n } from "../i18n";

interface Props {
  status: WsStatus;
}

const COLOR: Record<WsStatus, string> = {
  open: "#22c55e",
  connecting: "#f59e0b",
  reconnecting: "#ef4444",
};

const TOOLTIP_KEY: Record<WsStatus, string> = {
  open: "ws.open",
  connecting: "ws.connecting",
  reconnecting: "ws.reconnecting",
};

const LABEL_KEY: Record<WsStatus, string> = {
  open: "app.live",
  connecting: "app.connecting",
  reconnecting: "app.reconnecting",
};

export function WsStatusBadge({ status }: Props) {
  const { t } = useI18n();
  const color = COLOR[status];
  const breathing = status !== "open";

  return (
    <Tooltip title={t(TOOLTIP_KEY[status])} placement="bottom">
      <Box
        sx={{
          display: "inline-flex",
          alignItems: "center",
          gap: 0.75,
          px: 1,
          py: 0.25,
          borderRadius: 1,
          background: (theme) =>
            theme.palette.mode === "dark"
              ? "rgba(255,255,255,0.04)"
              : "rgba(0,0,0,0.03)",
          border: 1,
          borderColor: "divider",
          fontSize: 11,
          fontFamily: "ui-monospace, monospace",
          letterSpacing: 0.4,
          textTransform: "uppercase",
          color: "text.secondary",
        }}
      >
        <Box
          sx={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            backgroundColor: color,
            boxShadow: `0 0 0 0 ${color}66`,
            animation: breathing ? "pulse 1.4s ease-out infinite" : "none",
            "@keyframes pulse": {
              "0%": { boxShadow: `0 0 0 0 ${color}aa` },
              "70%": { boxShadow: `0 0 0 6px ${color}00` },
              "100%": { boxShadow: `0 0 0 0 ${color}00` },
            },
          }}
        />
        {t(LABEL_KEY[status])}
      </Box>
    </Tooltip>
  );
}
