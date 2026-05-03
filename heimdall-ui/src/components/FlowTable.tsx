import { useMemo } from "react";
import {
  DataGrid,
  type GridColDef,
  type GridRowParams,
  type GridSortDirection,
} from "@mui/x-data-grid";
import { Box, Chip, Tooltip, Typography } from "@mui/material";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutline";
import dayjs from "dayjs";
import type { Flow } from "../types";
import { connectionColor } from "../theme";

interface Props {
  flows: readonly Flow[];
  selectedId: number | null;
  onSelect: (id: number | null) => void;
}

const sortModel: { field: string; sort: GridSortDirection }[] = [
  { field: "id", sort: "desc" },
];

export function FlowTable({ flows, selectedId, onSelect }: Props) {
  const columns: GridColDef<Flow>[] = useMemo(
    () => [
      {
        field: "id",
        headerName: "id",
        width: 70,
        type: "number",
        renderCell: (params) =>
          params.row.error ? (
            <Tooltip title={params.row.error}>
              <Box
                sx={{ display: "inline-flex", alignItems: "center", gap: 0.5 }}
              >
                <ErrorOutlineIcon
                  fontSize="small"
                  color="error"
                  sx={{ fontSize: 14 }}
                />
                <Typography
                  variant="body2"
                  color="error"
                  sx={{ fontFamily: "ui-monospace, monospace" }}
                >
                  {params.row.id}
                </Typography>
              </Box>
            </Tooltip>
          ) : (
            <Typography
              variant="body2"
              sx={{ fontFamily: "ui-monospace, monospace" }}
            >
              {params.row.id}
            </Typography>
          ),
      },
      {
        field: "ts_start_us",
        headerName: "time",
        width: 105,
        valueGetter: (_v, row) => row.ts_start_us,
        renderCell: (params) => (
          <Typography
            variant="body2"
            sx={{ fontFamily: "ui-monospace, monospace" }}
          >
            {dayjs(params.row.ts_start_us / 1000).format("HH:mm:ss.SSS")}
          </Typography>
        ),
      },
      {
        field: "pod",
        headerName: "pod",
        flex: 1.2,
        minWidth: 220,
        valueGetter: (_v, row) =>
          row.pod_name && row.namespace
            ? `${row.namespace}/${row.pod_name}`
            : "—",
      },
      {
        field: "connection_name",
        headerName: "conn",
        width: 110,
        renderCell: (params) => (
          <Chip
            label={params.row.connection_name}
            size="small"
            color={connectionColor(params.row.connection_name)}
            variant="filled"
            sx={{ fontWeight: 500 }}
          />
        ),
      },
      {
        field: "dst_host",
        headerName: "dst",
        flex: 1.5,
        minWidth: 220,
        valueGetter: (_v, row) => row.dst_host ?? row.dst_ip,
        renderCell: (params) => (
          <Tooltip title={`${params.row.dst_ip}:${params.row.dst_port}`}>
            <Typography
              variant="body2"
              sx={{
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {params.row.dst_host ?? params.row.dst_ip}
            </Typography>
          </Tooltip>
        ),
      },
      {
        field: "dst_port",
        headerName: "port",
        width: 70,
        type: "number",
        align: "right",
        headerAlign: "right",
      },
      {
        field: "bytes_up",
        headerName: "↑",
        width: 80,
        type: "number",
        align: "right",
        headerAlign: "right",
        renderCell: (params) => (
          <Typography variant="body2" sx={{ fontFamily: "ui-monospace, monospace" }}>
            {humanBytes(params.row.bytes_up)}
          </Typography>
        ),
      },
      {
        field: "bytes_down",
        headerName: "↓",
        width: 90,
        type: "number",
        align: "right",
        headerAlign: "right",
        renderCell: (params) => (
          <Typography variant="body2" sx={{ fontFamily: "ui-monospace, monospace" }}>
            {humanBytes(params.row.bytes_down)}
          </Typography>
        ),
      },
      {
        field: "duration",
        headerName: "dur",
        width: 75,
        type: "number",
        align: "right",
        headerAlign: "right",
        valueGetter: (_v, row) =>
          row.ts_end_us != null
            ? Math.max(0, Math.round((row.ts_end_us - row.ts_start_us) / 1000))
            : null,
        renderCell: (params) =>
          params.value == null ? (
            <Typography variant="body2" color="text.disabled">
              …
            </Typography>
          ) : (
            <Typography variant="body2" sx={{ fontFamily: "ui-monospace, monospace" }}>
              {`${params.value as number}ms`}
            </Typography>
          ),
      },
      {
        field: "upstream_addr",
        headerName: "via",
        width: 180,
        valueGetter: (_v, row) => row.upstream_addr ?? "—",
        renderCell: (params) => (
          <Typography
            variant="body2"
            sx={{ fontFamily: "ui-monospace, monospace" }}
            color="text.secondary"
          >
            {params.row.upstream_addr ?? "—"}
          </Typography>
        ),
      },
    ],
    [],
  );

  return (
    <DataGrid
      rows={flows as Flow[]}
      columns={columns}
      density="compact"
      disableRowSelectionOnClick={false}
      onRowClick={(params: GridRowParams<Flow>) =>
        onSelect(params.row.id === selectedId ? null : params.row.id)
      }
      rowSelectionModel={selectedId != null ? [selectedId] : []}
      initialState={{
        sorting: { sortModel },
        pagination: { paginationModel: { pageSize: 100, page: 0 } },
      }}
      pageSizeOptions={[50, 100, 250, 500]}
      sx={{
        border: 0,
        "& .MuiDataGrid-row": { cursor: "pointer" },
        "& .MuiDataGrid-cell:focus, & .MuiDataGrid-cell:focus-within": {
          outline: "none",
        },
        "& .MuiDataGrid-columnHeader:focus, & .MuiDataGrid-columnHeader:focus-within":
          { outline: "none" },
      }}
    />
  );
}

function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
