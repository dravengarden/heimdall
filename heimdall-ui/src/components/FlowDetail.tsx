import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Chip,
  Drawer,
  IconButton,
  Snackbar,
  Tab,
  Tabs,
  Tooltip,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import ReplayIcon from "@mui/icons-material/Replay";
import dayjs from "dayjs";
import type { Flow, Message } from "../types";
import { fetchFlow, fetchFlowMessages } from "../api/client";
import { connectionColor } from "../theme";
import { copyText } from "../util/clipboard";
import { useI18n } from "../i18n";
import { MessageBlock } from "./MessageBlock";

interface Props {
  flowId: number | null;
  onClose: () => void;
  fallback?: Flow | undefined;
}

const DRAWER_WIDTH = 560;

export function FlowDetail({ flowId, onClose, fallback }: Props) {
  const [flow, setFlow] = useState<Flow | null>(null);
  const [tab, setTab] = useState<"overview" | "plaintext" | "raw">("overview");
  const [toast, setToast] = useState<string | null>(null);
  const { t } = useI18n();

  useEffect(() => {
    if (flowId == null) {
      setFlow(null);
      return;
    }
    setFlow(fallback ?? null);
    let cancelled = false;
    fetchFlow(flowId)
      .then((f) => {
        if (!cancelled) setFlow(f);
      })
      .catch(() => {
        /* keep fallback */
      });
    return () => {
      cancelled = true;
    };
  }, [flowId, fallback]);

  const showToast = async (text: string, label: string): Promise<void> => {
    const ok = await copyText(text);
    setToast(ok ? t("toast.copied", label) : t("toast.copyFailed", label));
  };

  const onReplay = (): void => {
    // Phase B will hook this up to POST /api/flows/:id/replay once we
    // have plaintext from the uprobe layer.
    setToast(t("detail.replay.todo"));
  };

  return (
    <>
      <Drawer
        anchor="right"
        open={flowId != null}
        onClose={onClose}
        slotProps={{
          paper: {
            sx: {
              width: DRAWER_WIDTH,
              maxWidth: "90vw",
              background: (t) => t.palette.background.paper,
              borderLeft: 1,
              borderColor: "divider",
            },
          },
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", px: 2, py: 1 }}>
          <Typography variant="h6">
            {flow ? `flow #${flow.id}` : "flow"}
          </Typography>
          {flow && (
            <Chip
              label={flow.connection_name}
              size="small"
              color={connectionColor(flow.connection_name)}
              sx={{ ml: 1.5 }}
            />
          )}
          <Box sx={{ flex: 1 }} />
          {flow && (
            <>
              <Tooltip title={t("detail.replay")}>
                <IconButton
                  size="small"
                  onClick={onReplay}
                  aria-label="replay"
                >
                  <ReplayIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title={t("detail.copyJson")}>
                <IconButton
                  size="small"
                  onClick={() =>
                    void showToast(JSON.stringify(flow, null, 2), "JSON")
                  }
                  aria-label="copy json"
                >
                  <ContentCopyIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </>
          )}
          <IconButton size="small" onClick={onClose} aria-label="close">
            <CloseIcon />
          </IconButton>
        </Box>

        <Tabs
          value={tab}
          onChange={(_, v: "overview" | "plaintext" | "raw") => setTab(v)}
          sx={{ borderBottom: 1, borderColor: "divider", px: 1 }}
        >
          <Tab value="overview" label={t("detail.tabs.overview")} />
          <Tab value="plaintext" label={t("detail.tabs.plaintext")} />
          <Tab value="raw" label={t("detail.tabs.raw")} />
        </Tabs>

        <Box sx={{ flex: 1, overflow: "auto", px: 2, py: 2 }}>
          {flow == null ? (
            <Typography color="text.secondary">loading…</Typography>
          ) : tab === "overview" ? (
            <Overview
              flow={flow}
              onCopy={(text, label) => void showToast(text, label)}
            />
          ) : tab === "plaintext" ? (
            <Plaintext flowId={flow.id} />
          ) : (
            <RawJson flow={flow} />
          )}
        </Box>
      </Drawer>

      <Snackbar
        open={toast != null}
        autoHideDuration={2000}
        onClose={() => setToast(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      >
        <Alert
          severity="success"
          variant="filled"
          onClose={() => setToast(null)}
          sx={{ alignItems: "center" }}
        >
          {toast}
        </Alert>
      </Snackbar>
    </>
  );
}

interface OverviewProps {
  flow: Flow;
  onCopy: (text: string, label: string) => void;
}

function Overview({ flow, onCopy }: OverviewProps) {
  const { t } = useI18n();
  const dur =
    flow.ts_end_us != null
      ? `${Math.max(0, Math.round((flow.ts_end_us - flow.ts_start_us) / 1000))} ms`
      : "(open)";
  const fields: ReadonlyArray<{
    k: string;
    v: string | null;
    copyValue?: string;
    copyLabel?: string;
  }> = [
    { k: "pod", v: podLabel(flow), copyLabel: "pod" },
    { k: "pod_uid", v: flow.pod_uid, copyLabel: "pod_uid" },
    { k: "connection", v: flow.connection_name },
    {
      k: "dst host",
      v: flow.dst_host,
      copyLabel: "hostname",
    },
    {
      k: "dst",
      v: flow.dst_ip.includes(":")
        ? `[${flow.dst_ip}]:${flow.dst_port}`
        : `${flow.dst_ip}:${flow.dst_port}`,
      copyLabel: "ip:port",
    },
    { k: "upstream", v: flow.upstream_addr, copyLabel: "upstream" },
    { k: "socks5 atyp", v: flow.atyp },
    { k: "bytes ↑", v: `${flow.bytes_up}` },
    { k: "bytes ↓", v: `${flow.bytes_down}` },
    { k: "duration", v: dur },
    {
      k: "ts_start",
      v: dayjs(flow.ts_start_us / 1000).format("YYYY-MM-DD HH:mm:ss.SSS"),
    },
    {
      k: "ts_end",
      v:
        flow.ts_end_us != null
          ? dayjs(flow.ts_end_us / 1000).format("YYYY-MM-DD HH:mm:ss.SSS")
          : "(open)",
    },
    {
      k: "cgroup_id",
      v: flow.cgroup_id != null ? String(flow.cgroup_id) : null,
    },
  ];

  return (
    <>
      {flow.error && (
        <Box
          sx={{
            mb: 2,
            p: 1.25,
            border: 1,
            borderColor: "error.main",
            borderRadius: 1,
            background: (t) => `${t.palette.error.main}1a`,
          }}
        >
          <Typography variant="caption" color="error">
            error
          </Typography>
          <Typography
            variant="body2"
            sx={{ fontFamily: "ui-monospace, monospace" }}
          >
            {flow.error}
          </Typography>
        </Box>
      )}

      <SectionHeader>{t("detail.section.identity")}</SectionHeader>
      <Grid>
        {fields.slice(0, 3).map((f) => (
          <Row key={f.k} field={f} onCopy={onCopy} />
        ))}
      </Grid>

      <SectionHeader>{t("detail.section.dst")}</SectionHeader>
      <Grid>
        {fields.slice(3, 7).map((f) => (
          <Row key={f.k} field={f} onCopy={onCopy} />
        ))}
      </Grid>

      <SectionHeader>{t("detail.section.traffic")}</SectionHeader>
      <Grid>
        {fields.slice(7, 10).map((f) => (
          <Row key={f.k} field={f} onCopy={onCopy} />
        ))}
      </Grid>

      <SectionHeader>{t("detail.section.timing")}</SectionHeader>
      <Grid>
        {fields.slice(10, 12).map((f) => (
          <Row key={f.k} field={f} onCopy={onCopy} />
        ))}
      </Grid>

      <SectionHeader>{t("detail.section.internals")}</SectionHeader>
      <Grid>
        <Row
          field={{
            k: "cgroup_id",
            v: fields[12]?.v ?? null,
          }}
          onCopy={onCopy}
        />
      </Grid>
    </>
  );
}

function SectionHeader({ children }: { children: string }) {
  return (
    <Typography
      variant="caption"
      sx={{
        display: "block",
        mt: 2,
        mb: 0.5,
        textTransform: "uppercase",
        letterSpacing: 0.5,
        color: "text.disabled",
      }}
    >
      {children}
    </Typography>
  );
}

function Grid({ children }: { children: React.ReactNode }) {
  return (
    <Box
      sx={{
        display: "grid",
        gridTemplateColumns: "120px 1fr auto",
        rowGap: 0.5,
        alignItems: "center",
      }}
    >
      {children}
    </Box>
  );
}

function Row({
  field,
  onCopy,
}: {
  field: { k: string; v: string | null; copyValue?: string; copyLabel?: string };
  onCopy: (text: string, label: string) => void;
}) {
  const display = field.v ?? "—";
  const empty = field.v == null;
  return (
    <>
      <Typography variant="caption" color="text.secondary" sx={{ pt: 0.25 }}>
        {field.k}
      </Typography>
      <Typography
        variant="body2"
        sx={{
          fontFamily: "ui-monospace, monospace",
          wordBreak: "break-all",
          color: empty ? "text.disabled" : "text.primary",
        }}
      >
        {display}
      </Typography>
      {!empty && field.copyLabel ? (
        <Tooltip title={`Copy ${field.copyLabel}`}>
          <IconButton
            size="small"
            sx={{ ml: 0.5 }}
            onClick={() =>
              onCopy(field.copyValue ?? (field.v as string), field.copyLabel as string)
            }
            aria-label={`copy ${field.copyLabel}`}
          >
            <ContentCopyIcon sx={{ fontSize: 14 }} />
          </IconButton>
        </Tooltip>
      ) : (
        <Box />
      )}
    </>
  );
}

function RawJson({ flow }: { flow: Flow }) {
  return (
    <Box
      component="pre"
      sx={{
        m: 0,
        p: 1.5,
        background: "rgba(255,255,255,0.03)",
        borderRadius: 1,
        fontSize: 12,
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
      }}
    >
      {JSON.stringify(flow, null, 2)}
    </Box>
  );
}

// ─── Plaintext tab — eBPF uprobe-captured TLS plaintext ────────────────

function Plaintext({ flowId }: { flowId: number }) {
  const [msgs, setMsgs] = useState<readonly Message[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const { t } = useI18n();

  useEffect(() => {
    let cancelled = false;
    setMsgs(null);
    setErr(null);
    fetchFlowMessages(flowId, { limit: 1000 })
      .then((rows) => {
        if (!cancelled) setMsgs(rows);
      })
      .catch((e: unknown) => {
        if (!cancelled) setErr(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [flowId]);

  if (err != null) {
    return (
      <Alert severity="error" variant="outlined">
        {err}
      </Alert>
    );
  }
  if (msgs == null) {
    return <Typography color="text.secondary">loading…</Typography>;
  }
  if (msgs.length === 0) {
    return (
      <Alert severity="info" variant="outlined">
        {t("detail.plaintext.empty")}
      </Alert>
    );
  }

  return (
    <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
      {msgs.map((m) => (
        <MessageBlock key={m.id} msg={m} />
      ))}
    </Box>
  );
}
function podLabel(flow: Flow): string | null {
  if (flow.namespace && flow.pod_name)
    return `${flow.namespace}/${flow.pod_name}`;
  return null;
}
