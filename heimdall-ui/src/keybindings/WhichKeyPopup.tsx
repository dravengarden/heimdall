import { useEffect, useState } from "react";
import { Box, Paper, Stack, Typography } from "@mui/material";
import { useKbState } from "./KeybindingsProvider";
import { chordTail, continuationsFor } from "./registry";

// Bottom-right which-key popup. Appears 250 ms after a chord prefix is
// armed; vanishes immediately when the chord completes or the prefix is
// cleared. Muscle-memory users (`g f` typed under 250 ms) never see it.
//
// Position + delay match LazyVim's `which-key.nvim` modern preset.
const SHOW_AFTER_MS = 250;

export function WhichKeyPopup() {
  const { pendingPrefix, activeScopes } = useKbState();
  const [shouldShow, setShouldShow] = useState(false);

  useEffect(() => {
    if (!pendingPrefix) {
      setShouldShow(false);
      return;
    }
    const t = window.setTimeout(() => setShouldShow(true), SHOW_AFTER_MS);
    return () => window.clearTimeout(t);
  }, [pendingPrefix]);

  if (!pendingPrefix || !shouldShow) return null;

  const items = continuationsFor(pendingPrefix, activeScopes);
  if (items.length === 0) return null;

  return (
    <Paper
      elevation={6}
      sx={{
        position: "fixed",
        right: 16,
        bottom: 40, // sit above the StatusChip so they don't overlap
        zIndex: (t) => t.zIndex.tooltip + 1,
        minWidth: 240,
        maxWidth: 360,
        py: 0.75,
        px: 1.25,
        borderRadius: 1.5,
        // Discreet but visible — matches the dark/light theme.
        bgcolor: (t) =>
          t.palette.mode === "dark" ? "background.paper" : "background.paper",
        border: 1,
        borderColor: "divider",
      }}
      role="dialog"
      aria-label={`Continuations for ${pendingPrefix}`}
    >
      <Typography
        variant="caption"
        sx={{ color: "text.secondary", fontFamily: "monospace", fontSize: 11 }}
      >
        {pendingPrefix} …
      </Typography>
      <Stack spacing={0.25} sx={{ mt: 0.5 }}>
        {items.map((b) => (
          <Box
            key={b.id}
            sx={{
              display: "grid",
              gridTemplateColumns: "20px 1fr",
              alignItems: "center",
              gap: 1,
              fontSize: 12,
              lineHeight: 1.6,
            }}
          >
            <Box
              sx={{
                fontFamily: "monospace",
                color: "warning.main",
                textAlign: "center",
                fontWeight: 600,
              }}
            >
              {chordTail(b)}
            </Box>
            <Box sx={{ color: "text.primary" }}>{b.desc}</Box>
          </Box>
        ))}
      </Stack>
    </Paper>
  );
}
