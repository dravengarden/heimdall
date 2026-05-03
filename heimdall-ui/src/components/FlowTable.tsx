import { useMemo } from "react";
import {
  DataGrid,
  GridToolbarColumnsButton,
  GridToolbarContainer,
  GridToolbarDensitySelector,
  type GridColDef,
  type GridRowParams,
  type GridSortDirection,
} from "@mui/x-data-grid";
import { Box, Chip, Stack, Tooltip, Typography } from "@mui/material";
import ErrorOutlineIcon from "@mui/icons-material/ErrorOutline";
import RouterOutlinedIcon from "@mui/icons-material/RouterOutlined";
import dayjs from "dayjs";
import type { Flow } from "../types";
import { connectionColor } from "../theme";
import { useI18n } from "../i18n";

interface Props {
  flows: readonly Flow[];
  selectedId: number | null;
  onSelect: (id: number | null) => void;
}

const sortModel: { field: string; sort: GridSortDirection }[] = [
  { field: "id", sort: "desc" },
];

const MONO =
  'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';

const truncateSx = {
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
  width: "100%",
} as const;

export function FlowTable({ flows, selectedId, onSelect }: Props) {
  const { t } = useI18n();
  const columns: GridColDef<Flow>[] = useMemo(
    () => [
      {
        field: "id",
        headerName: t("table.cols.id"),
        width: 64,
        align: "right",
        headerAlign: "right",
        sortable: true,
        renderCell: (params) =>
          params.row.error ? (
            <Tooltip title={params.row.error} placement="right">
              <Box
                sx={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: 0.5,
                  fontFamily: MONO,
                  color: "error.main",
                }}
              >
                <ErrorOutlineIcon sx={{ fontSize: 14 }} />
                {params.row.id}
              </Box>
            </Tooltip>
          ) : (
            <Box sx={{ fontFamily: MONO, color: "text.secondary" }}>
              {params.row.id}
            </Box>
          ),
      },
      {
        field: "ts_start_us",
        headerName: t("table.cols.time"),
        width: 110,
        sortable: true,
        valueGetter: (_v, row) => row.ts_start_us,
        renderCell: (params) => (
          <Box sx={{ fontFamily: MONO }}>
            {dayjs(params.row.ts_start_us / 1000).format("HH:mm:ss.SSS")}
          </Box>
        ),
      },
      {
        field: "pod",
        headerName: t("table.cols.pod"),
        flex: 1,
        minWidth: 220,
        sortable: true,
        valueGetter: (_v, row) =>
          row.pod_name && row.namespace
            ? `${row.namespace}/${row.pod_name}`
            : "",
        renderCell: (params) => {
          const label = params.value as string;
          return label ? (
            <Box sx={{ ...truncateSx }}>{label}</Box>
          ) : (
            <Box sx={{ color: "text.disabled" }}>—</Box>
          );
        },
      },
      {
        field: "connection_name",
        headerName: t("table.cols.conn"),
        width: 96,
        sortable: true,
        renderCell: (params) => (
          <Chip
            label={params.row.connection_name}
            size="small"
            color={connectionColor(params.row.connection_name)}
            variant="filled"
            sx={{ fontWeight: 500, height: 22, fontSize: 11 }}
          />
        ),
      },
      {
        field: "dst_host",
        headerName: t("table.cols.dst"),
        flex: 1.6,
        minWidth: 220,
        sortable: true,
        valueGetter: (_v, row) => row.dst_host ?? row.dst_ip,
        renderCell: (params) => (
          <Tooltip
            title={`${params.row.dst_ip}:${params.row.dst_port}`}
            placement="top"
          >
            <Box sx={{ ...truncateSx, fontFamily: MONO }}>
              {params.row.dst_host ?? params.row.dst_ip}
            </Box>
          </Tooltip>
        ),
      },
      {
        field: "dst_port",
        headerName: t("table.cols.port"),
        width: 64,
        align: "right",
        headerAlign: "right",
        sortable: true,
        valueGetter: (_v, row) => row.dst_port,
        // Plain integer — DataGrid's number type would add locale separators.
        renderCell: (params) => (
          <Box sx={{ fontFamily: MONO }}>{params.row.dst_port}</Box>
        ),
      },
      {
        field: "bytes_up",
        headerName: "↑",
        width: 76,
        align: "right",
        headerAlign: "right",
        sortable: true,
        valueGetter: (_v, row) => row.bytes_up,
        renderCell: (params) => (
          <Box sx={{ fontFamily: MONO }}>
            {humanBytes(params.row.bytes_up)}
          </Box>
        ),
      },
      {
        field: "bytes_down",
        headerName: "↓",
        width: 80,
        align: "right",
        headerAlign: "right",
        sortable: true,
        valueGetter: (_v, row) => row.bytes_down,
        renderCell: (params) => (
          <Box sx={{ fontFamily: MONO }}>
            {humanBytes(params.row.bytes_down)}
          </Box>
        ),
      },
      {
        field: "duration",
        headerName: t("table.cols.dur"),
        width: 76,
        align: "right",
        headerAlign: "right",
        sortable: true,
        valueGetter: (_v, row) =>
          row.ts_end_us != null
            ? Math.max(0, Math.round((row.ts_end_us - row.ts_start_us) / 1000))
            : null,
        renderCell: (params) =>
          params.value == null ? (
            <Box sx={{ color: "text.disabled" }}>…</Box>
          ) : (
            <Box sx={{ fontFamily: MONO }}>{`${params.value as number}ms`}</Box>
          ),
      },
      {
        field: "upstream_addr",
        headerName: t("table.cols.via"),
        width: 168,
        sortable: true,
        valueGetter: (_v, row) => row.upstream_addr ?? "",
        renderCell: (params) => (
          <Box sx={{ fontFamily: MONO, color: "text.secondary" }}>
            {params.row.upstream_addr ?? "—"}
          </Box>
        ),
      },
    ],
    [t],
  );

  return (
    <DataGrid
      rows={flows as Flow[]}
      columns={columns}
      density="compact"
      slots={{ toolbar: GridToolbar, noRowsOverlay: NoRowsOverlay }}
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
        fontSize: 12.5,
        "& .MuiDataGrid-row": { cursor: "pointer" },
        "& .MuiDataGrid-cell": {
          display: "flex",
          alignItems: "center",
          // Uniform horizontal padding so left/right-aligned columns
          // line up neatly without big variable gaps.
          paddingInline: "10px",
        },
        "& .MuiDataGrid-columnHeader": {
          paddingInline: "10px",
        },
        "& .MuiDataGrid-columnHeaderTitle": {
          fontWeight: 600,
          fontSize: 12,
          letterSpacing: 0.3,
          textTransform: "uppercase",
          color: "text.secondary",
        },
        "& .MuiDataGrid-cell:focus, & .MuiDataGrid-cell:focus-within": {
          outline: "none",
        },
        "& .MuiDataGrid-columnHeader:focus, & .MuiDataGrid-columnHeader:focus-within":
          { outline: "none" },
        "& .MuiDataGrid-columnSeparator": { display: "none" },
        "& .MuiDataGrid-footerContainer": {
          borderTop: 1,
          borderColor: "divider",
        },
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

function NoRowsOverlay() {
  // useI18n is fine here — DataGrid renders this slot inside the same
  // React tree as the rest of the app.
  const { t } = useI18n();
  return (
    <Stack
      sx={{ height: "100%" }}
      alignItems="center"
      justifyContent="center"
      spacing={1}
    >
      <RouterOutlinedIcon sx={{ fontSize: 40, color: "text.disabled" }} />
      <Typography variant="body2" color="text.secondary">
        {t("table.empty.title")}
      </Typography>
      <Typography variant="caption" color="text.disabled">
        {t("table.empty.hint")}
      </Typography>
    </Stack>
  );
}

function GridToolbar() {
  return (
    <GridToolbarContainer sx={{ px: 1, py: 0.5, gap: 0.5 }}>
      <GridToolbarColumnsButton />
      <GridToolbarDensitySelector />
    </GridToolbarContainer>
  );
}
