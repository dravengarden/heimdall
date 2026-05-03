import { Box, Tooltip } from "@mui/material";
import type { WsStatus } from "../api/ws";

interface Props {
  status: WsStatus;
}

const COLOR: Record<WsStatus, string> = {
  open: "#22c55e",
  connecting: "#f59e0b",
  reconnecting: "#ef4444",
};

const LABEL: Record<WsStatus, string> = {
  open: "Live updates connected",
  connecting: "Connecting to daemon…",
  reconnecting: "Reconnecting to daemon…",
};

export function WsStatusBadge({ status }: Props) {
  const color = COLOR[status];
  const breathing = status !== "open";

  return (
    <Tooltip title={LABEL[status]} placement="bottom">
      <Box
        sx={{
          display: "inline-flex",
          alignItems: "center",
          gap: 0.75,
          px: 1,
          py: 0.25,
          borderRadius: 1,
          background: "rgba(255,255,255,0.04)",
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
        {status === "open" ? "live" : status}
      </Box>
    </Tooltip>
  );
}
