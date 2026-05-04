import { useMemo, useState } from "react";
import {
  Alert,
  Box,
  Chip,
  IconButton,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from "@mui/material";
import ClearAllIcon from "@mui/icons-material/ClearAll";
import PauseIcon from "@mui/icons-material/PauseCircleOutline";
import PlayIcon from "@mui/icons-material/PlayCircleOutline";
import { useLiveTap } from "../hooks/useLiveTap";
import { MessageBlock } from "./MessageBlock";
import { useI18n } from "../i18n";

/**
 * Live plaintext stream — surfaces every libssl uprobe event the daemon
 * captures, regardless of flow correlation. Useful for:
 *   - Verifying the tap is actually running on the host.
 *   - Debugging why a flow's Plaintext tab is empty (filter by cgroup).
 *   - tcpdump-style live observation of decrypted TLS traffic.
 */
export function LiveTapView() {
  const { t } = useI18n();
  const [cgroupFilter, setCgroupFilter] = useState<string>("");
  const [podFilter, setPodFilter] = useState<string>("");
  const cgroupId = useMemo<number | null>(() => {
    const trimmed = cgroupFilter.trim();
    if (trimmed === "") return null;
    const n = Number(trimmed);
    return Number.isFinite(n) && n > 0 ? n : null;
  }, [cgroupFilter]);

  const tap = useLiveTap({ intervalMs: 1000, cgroupId });

  // The pod filter runs purely client-side: the API doesn't have a
  // pod-substring filter (would require joining cgroup → pod on every
  // SQL row, expensive), and the volume on the live tap is bounded to
  // the 1000-msg ring anyway. Substring match across `ns/name`.
  const filteredMsgs = useMemo(() => {
    const needle = podFilter.trim().toLowerCase();
    if (needle === "") return tap.msgs;
    return tap.msgs.filter((m) => {
      if (!m.pod_namespace || !m.pod_name) return false;
      return `${m.pod_namespace}/${m.pod_name}`.toLowerCase().includes(needle);
    });
  }, [tap.msgs, podFilter]);

  return (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 1.5,
          px: 2,
          py: 1,
          borderBottom: 1,
          borderColor: "divider",
          background: (theme) => theme.palette.background.paper,
        }}
      >
        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
          {t("livetap.title")}
        </Typography>
        <Chip
          size="small"
          label={
            podFilter.trim() === ""
              ? `${tap.msgs.length}`
              : `${filteredMsgs.length} / ${tap.msgs.length}`
          }
          variant="outlined"
          sx={{ fontFamily: "ui-monospace, monospace" }}
        />
        <TextField
          size="small"
          placeholder={t("livetap.podFilter")}
          value={podFilter}
          onChange={(e) => setPodFilter(e.target.value)}
          sx={{ width: 280, ml: 1 }}
          slotProps={{
            input: { sx: { fontFamily: "ui-monospace, monospace" } },
          }}
        />
        <TextField
          size="small"
          placeholder={t("livetap.cgroupFilter")}
          value={cgroupFilter}
          onChange={(e) => setCgroupFilter(e.target.value)}
          sx={{ width: 180 }}
          slotProps={{
            input: { sx: { fontFamily: "ui-monospace, monospace" } },
          }}
        />
        <Box sx={{ flex: 1 }} />
        <Stack direction="row" spacing={0.5}>
          <Tooltip
            title={tap.paused ? t("livetap.resume") : t("livetap.pause")}
          >
            <IconButton
              size="small"
              onClick={() => tap.setPaused(!tap.paused)}
              aria-label="pause live tap"
            >
              {tap.paused ? (
                <PlayIcon fontSize="small" color="warning" />
              ) : (
                <PauseIcon fontSize="small" />
              )}
            </IconButton>
          </Tooltip>
          <Tooltip title={t("livetap.clear")}>
            <IconButton
              size="small"
              onClick={tap.clear}
              aria-label="clear live tap"
            >
              <ClearAllIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      </Box>

      <Box sx={{ flex: 1, minHeight: 0, overflow: "auto", p: 2 }}>
        {tap.err != null ? (
          <Alert severity="error" variant="outlined" sx={{ mb: 2 }}>
            {tap.err}
          </Alert>
        ) : null}
        {tap.loading && tap.msgs.length === 0 ? (
          <Typography color="text.secondary">loading…</Typography>
        ) : tap.msgs.length === 0 ? (
          <Alert severity="info" variant="outlined">
            {t("livetap.empty")}
          </Alert>
        ) : filteredMsgs.length === 0 ? (
          <Alert severity="warning" variant="outlined">
            {t("livetap.noMatch")}
          </Alert>
        ) : (
          <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
            {filteredMsgs.map((m) => (
              <MessageBlock key={m.id} msg={m} showCgroup />
            ))}
          </Box>
        )}
      </Box>
    </Box>
  );
}
