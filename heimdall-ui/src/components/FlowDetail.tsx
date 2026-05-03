import { useEffect, useState } from "react";
import {
  Box,
  Chip,
  Drawer,
  IconButton,
  Tab,
  Tabs,
  Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import dayjs from "dayjs";
import type { Flow } from "../types";
import { fetchFlow } from "../api/client";
import { connectionColor } from "../theme";

interface Props {
  flowId: number | null;
  onClose: () => void;
  fallback?: Flow | undefined;
}

const DRAWER_WIDTH = 540;

export function FlowDetail({ flowId, onClose, fallback }: Props) {
  const [flow, setFlow] = useState<Flow | null>(null);
  const [tab, setTab] = useState<"overview" | "raw">("overview");

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

  return (
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
        <IconButton size="small" onClick={onClose}>
          <CloseIcon />
        </IconButton>
      </Box>

      <Tabs
        value={tab}
        onChange={(_, v: "overview" | "raw") => setTab(v)}
        sx={{ borderBottom: 1, borderColor: "divider", px: 1 }}
      >
        <Tab value="overview" label="Overview" />
        <Tab value="raw" label="Raw JSON" />
      </Tabs>

      <Box sx={{ flex: 1, overflow: "auto", px: 2, py: 2 }}>
        {flow == null ? (
          <Typography color="text.secondary">loading…</Typography>
        ) : tab === "overview" ? (
          <Overview flow={flow} />
        ) : (
          <RawJson flow={flow} />
        )}
      </Box>
    </Drawer>
  );
}

function Overview({ flow }: { flow: Flow }) {
  const dur =
    flow.ts_end_us != null
      ? `${Math.max(0, Math.round((flow.ts_end_us - flow.ts_start_us) / 1000))} ms`
      : "(open)";
  const fields: ReadonlyArray<readonly [string, string | null]> = [
    ["pod", podLabel(flow)],
    ["pod_uid", flow.pod_uid],
    ["connection", flow.connection_name],
    ["dst host", flow.dst_host],
    ["dst", `${flow.dst_ip}:${flow.dst_port}`],
    ["upstream", flow.upstream_addr],
    ["socks5 atyp", flow.atyp],
    ["bytes ↑", `${flow.bytes_up}`],
    ["bytes ↓", `${flow.bytes_down}`],
    ["duration", dur],
    ["ts_start", dayjs(flow.ts_start_us / 1000).format("YYYY-MM-DD HH:mm:ss.SSS")],
    [
      "ts_end",
      flow.ts_end_us != null
        ? dayjs(flow.ts_end_us / 1000).format("YYYY-MM-DD HH:mm:ss.SSS")
        : "(open)",
    ],
    ["cgroup_id", flow.cgroup_id != null ? String(flow.cgroup_id) : null],
  ] as const;

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
          <Typography variant="body2" sx={{ fontFamily: "ui-monospace, monospace" }}>
            {flow.error}
          </Typography>
        </Box>
      )}
      <Box sx={{ display: "grid", gridTemplateColumns: "120px 1fr", rowGap: 1 }}>
        {fields.map(([k, v]) => (
          <Row key={k} k={k} v={v ?? "—"} />
        ))}
      </Box>
    </>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <Typography variant="caption" color="text.secondary" sx={{ pt: 0.25 }}>
        {k}
      </Typography>
      <Typography
        variant="body2"
        sx={{
          fontFamily: "ui-monospace, monospace",
          wordBreak: "break-all",
        }}
      >
        {v}
      </Typography>
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

function podLabel(flow: Flow): string | null {
  if (flow.namespace && flow.pod_name) return `${flow.namespace}/${flow.pod_name}`;
  return null;
}
