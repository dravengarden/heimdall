import { Box, Chip, Typography } from "@mui/material";
import dayjs from "dayjs";
import type { Message } from "../types";
import { useI18n } from "../i18n";

interface Props {
  msg: Message;
  /** Show cgroup_id alongside tgid — useful in the live tap view where
   *  messages span multiple processes and pods. */
  showCgroup?: boolean;
}

export function MessageBlock({ msg, showCgroup = false }: Props) {
  const { t } = useI18n();
  const isSend = msg.dir === 0;
  const truncated = msg.captured_len < msg.total_len;
  const ts = dayjs(msg.ts_us / 1000).format("HH:mm:ss.SSS");
  return (
    <Box
      sx={{
        border: 1,
        borderColor: "divider",
        borderRadius: 1,
        overflow: "hidden",
      }}
    >
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 1,
          px: 1,
          py: 0.5,
          background: (theme) =>
            isSend
              ? `${theme.palette.primary.main}1a`
              : `${theme.palette.success.main}1a`,
        }}
      >
        <Chip
          size="small"
          label={isSend ? t("detail.plaintext.send") : t("detail.plaintext.recv")}
          color={isSend ? "primary" : "success"}
          variant="filled"
          sx={{ height: 20, fontSize: 11 }}
        />
        <Typography
          variant="caption"
          sx={{ fontFamily: "ui-monospace, monospace", color: "text.secondary" }}
        >
          {ts}
        </Typography>
        <Typography
          variant="caption"
          sx={{ fontFamily: "ui-monospace, monospace", color: "text.secondary" }}
        >
          tgid={msg.tgid}
        </Typography>
        {showCgroup && (
          <Typography
            variant="caption"
            sx={{ fontFamily: "ui-monospace, monospace", color: "text.secondary" }}
          >
            cgroup={msg.cgroup_id}
          </Typography>
        )}
        {msg.flow_id != null && (
          <Chip
            size="small"
            label={`flow #${msg.flow_id}`}
            variant="outlined"
            sx={{ height: 20, fontSize: 11 }}
          />
        )}
        <Box sx={{ flex: 1 }} />
        <Typography
          variant="caption"
          sx={{ fontFamily: "ui-monospace, monospace", color: "text.secondary" }}
        >
          {truncated
            ? `${msg.captured_len} / ${msg.total_len} B`
            : `${msg.total_len} B`}
        </Typography>
      </Box>
      <Box
        component="pre"
        sx={{
          m: 0,
          px: 1.25,
          py: 0.75,
          background: "rgba(0,0,0,0.18)",
          fontFamily: "ui-monospace, monospace",
          fontSize: 11,
          lineHeight: 1.45,
          whiteSpace: "pre",
          overflowX: "auto",
        }}
      >
        {hexAscii(msg.body)}
      </Box>
    </Box>
  );
}

/** tcpdump-style hex + ASCII dump. */
export function hexAscii(bytes: readonly number[]): string {
  const lines: string[] = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hex = chunk
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(16 * 3 - 1, " ");
    const hexFmt =
      hex.slice(0, 8 * 3 - 1) + "  " + hex.slice(8 * 3 - 1).trimStart();
    const ascii = chunk
      .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(
      `${off.toString(16).padStart(4, "0")}  ${hexFmt.padEnd(48, " ")}  ${ascii}`,
    );
  }
  return lines.join("\n");
}
