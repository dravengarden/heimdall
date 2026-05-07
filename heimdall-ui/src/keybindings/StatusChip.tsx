import { Box, Typography } from "@mui/material";
import { useKbState } from "./KeybindingsProvider";

// Bottom-right persistent indicator. Shows scope context + pending
// chord prefix + hint mode hint. Clicking is unwired — the chip is
// purely informational; `?` opens the help overlay.
export function StatusChip() {
  const { pendingPrefix, hintActive, activeScopes } = useKbState();
  const scopeLabel = primaryScope(activeScopes);

  let pendingLabel = "";
  if (hintActive) pendingLabel = "HINT";
  else if (pendingPrefix) pendingLabel = `${pendingPrefix} …`;

  return (
    <Box
      sx={{
        position: "fixed",
        right: 10,
        bottom: 8,
        zIndex: (t) => t.zIndex.tooltip,
        px: 1,
        py: 0.25,
        borderRadius: 0.75,
        border: 1,
        borderColor: "divider",
        bgcolor: "background.paper",
        opacity: 0.85,
        display: "flex",
        gap: 1,
        alignItems: "baseline",
        fontSize: 11,
        fontFamily: "monospace",
        pointerEvents: "none",
        userSelect: "none",
      }}
      aria-hidden
    >
      <Typography
        component="span"
        sx={{ color: "text.secondary", fontFamily: "inherit", fontSize: 11 }}
      >
        {scopeLabel}
      </Typography>
      {pendingLabel && (
        <Typography
          component="span"
          sx={{
            color: hintActive ? "warning.main" : "info.main",
            fontFamily: "inherit",
            fontSize: 11,
            fontWeight: 600,
          }}
        >
          {pendingLabel}
        </Typography>
      )}
      <Typography
        component="span"
        sx={{ color: "text.disabled", fontFamily: "inherit", fontSize: 11 }}
      >
        ? help
      </Typography>
    </Box>
  );
}

function primaryScope(scopes: ReadonlySet<string>): string {
  if (scopes.has("drawer")) return "drawer";
  if (scopes.has("livetap")) return "tap";
  if (scopes.has("table")) return "table";
  return "global";
}
