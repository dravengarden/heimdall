import { useMemo, useState } from "react";
import {
  Box,
  Dialog,
  DialogContent,
  IconButton,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import { useKbState } from "./KeybindingsProvider";
import { BINDINGS, type Binding, type Scope } from "./registry";

// Full keymap reference — the `?` overlay. Renders every binding from
// the registry as grouped, two-column cards. Top-of-modal text input
// filters by binding description / keys, so an agent unsure where a
// command lives can type a substring.
//
// All text comes from the registry. Adding a binding there
// auto-extends this overlay; nothing to wire here.

const GROUP_TITLES: Record<Binding["group"], string> = {
  navigation: "Navigation",
  goto: "Go to",
  filter: "Filter",
  flow: "Flow",
  yank: "Yank",
  ui: "UI",
  tap: "Live tap",
  mode: "Modes",
};

const SCOPE_LABEL: Record<Scope, string> = {
  global: "global",
  table: "table",
  drawer: "drawer",
  livetap: "live tap",
  hint: "hint",
};

export function HelpOverlay() {
  const { helpOpen, setHelpOpen, activeScopes } = useKbState();
  const [query, setQuery] = useState("");

  const grouped = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matches = (b: Binding) => {
      if (!q) return true;
      return (
        b.desc.toLowerCase().includes(q) ||
        b.keys.toLowerCase().includes(q) ||
        b.group.toLowerCase().includes(q)
      );
    };
    const out = new Map<Binding["group"], Binding[]>();
    for (const b of BINDINGS) {
      if (!matches(b)) continue;
      const arr = out.get(b.group) ?? [];
      arr.push(b);
      out.set(b.group, arr);
    }
    return out;
  }, [query]);

  return (
    <Dialog
      open={helpOpen}
      onClose={() => setHelpOpen(false)}
      maxWidth="md"
      fullWidth
      // Don't trap focus inside the dialog the moment we open — the
      // modal's own keystroke handler reads from the same registry, so
      // the typed search input gets the keys directly.
      keepMounted={false}
    >
      <Stack
        direction="row"
        alignItems="center"
        spacing={1}
        sx={{ pl: 2, pr: 1, pt: 1.5 }}
      >
        <Typography variant="subtitle1" sx={{ fontWeight: 600, flexGrow: 0 }}>
          Keyboard
        </Typography>
        <Typography variant="caption" sx={{ color: "text.secondary", flexGrow: 0 }}>
          active scopes:{" "}
          {Array.from(activeScopes).map((s) => SCOPE_LABEL[s]).join(", ")}
        </Typography>
        <Box sx={{ flexGrow: 1 }}>
          <TextField
            fullWidth
            size="small"
            placeholder="Search bindings…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
          />
        </Box>
        <IconButton onClick={() => setHelpOpen(false)} size="small">
          <CloseIcon fontSize="small" />
        </IconButton>
      </Stack>
      <DialogContent sx={{ pt: 1.5 }}>
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" },
            gap: 2,
          }}
        >
          {Array.from(grouped.entries()).map(([group, items]) => (
            <Box key={group}>
              <Typography
                variant="overline"
                sx={{
                  color: "text.secondary",
                  fontWeight: 600,
                  letterSpacing: 0.6,
                }}
              >
                {GROUP_TITLES[group]}
              </Typography>
              <Stack spacing={0.5} sx={{ mt: 0.25 }}>
                {items.map((b) => (
                  <Box
                    key={b.id}
                    sx={{
                      display: "grid",
                      gridTemplateColumns: "92px 1fr 64px",
                      alignItems: "baseline",
                      gap: 1,
                      fontSize: 12.5,
                    }}
                  >
                    <Box
                      sx={{
                        fontFamily: "monospace",
                        color: "warning.main",
                        fontWeight: 600,
                      }}
                    >
                      {b.keys.replaceAll(">", " ").replaceAll(",", " · ")}
                    </Box>
                    <Box>{b.desc}</Box>
                    <Box sx={{ color: "text.disabled", fontSize: 11 }}>
                      {SCOPE_LABEL[b.scope]}
                    </Box>
                  </Box>
                ))}
              </Stack>
            </Box>
          ))}
        </Box>
        {grouped.size === 0 && (
          <Typography
            variant="body2"
            sx={{ color: "text.secondary", textAlign: "center", py: 4 }}
          >
            No bindings match {JSON.stringify(query)}
          </Typography>
        )}
      </DialogContent>
    </Dialog>
  );
}
