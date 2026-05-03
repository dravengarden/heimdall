import { createTheme } from "@mui/material/styles";

export const theme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: "#7c5cff" },
    secondary: { main: "#06b6d4" },
    background: {
      default: "#0a0e1a",
      paper: "#11162a",
    },
    success: { main: "#22c55e" },
    info: { main: "#06b6d4" },
    warning: { main: "#f59e0b" },
    error: { main: "#ef4444" },
    divider: "rgba(255,255,255,0.08)",
  },
  shape: { borderRadius: 8 },
  typography: {
    fontFamily:
      'Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
    fontSize: 13,
    h6: { fontWeight: 600, letterSpacing: 0.2 },
  },
  components: {
    MuiAppBar: {
      defaultProps: { color: "transparent", elevation: 0 },
      styleOverrides: {
        root: {
          backdropFilter: "blur(8px)",
          background: "rgba(17, 22, 42, 0.85)",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
        },
      },
    },
    MuiButton: { defaultProps: { disableElevation: true } },
    MuiPaper: {
      styleOverrides: {
        root: { backgroundImage: "none" },
      },
    },
    MuiTooltip: {
      styleOverrides: { tooltip: { fontSize: 11 } },
    },
  },
});

export const connectionColor = (name: string): "success" | "info" | "warning" | "default" => {
  switch (name) {
    case "default":
      return "success";
    case "conviva":
      return "info";
    case "bypass":
      return "warning";
    default:
      return "default";
  }
};
