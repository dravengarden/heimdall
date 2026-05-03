import { createTheme, type Theme } from "@mui/material/styles";

export type ThemeMode = "light" | "dark" | "auto";

const baseTypography = {
  fontFamily:
    'Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
  fontSize: 13,
  h6: { fontWeight: 600, letterSpacing: 0.2 },
} as const;

const baseShape = { borderRadius: 8 } as const;

const sharedComponents = (mode: "light" | "dark") => ({
  MuiAppBar: {
    defaultProps: { color: "transparent" as const, elevation: 0 },
    styleOverrides: {
      root: {
        backdropFilter: "blur(8px)",
        background:
          mode === "dark"
            ? "rgba(17, 22, 42, 0.85)"
            : "rgba(255, 255, 255, 0.85)",
        borderBottom: `1px solid ${
          mode === "dark" ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.08)"
        }`,
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
});

export function buildTheme(mode: "light" | "dark", fontSize: number): Theme {
  const dark = mode === "dark";
  return createTheme({
    palette: {
      mode,
      primary: { main: dark ? "#7c5cff" : "#5c3cff" },
      secondary: { main: "#06b6d4" },
      background: dark
        ? { default: "#0a0e1a", paper: "#11162a" }
        : { default: "#f5f6fa", paper: "#ffffff" },
      success: { main: dark ? "#22c55e" : "#15803d" },
      info: { main: dark ? "#06b6d4" : "#0891b2" },
      warning: { main: dark ? "#f59e0b" : "#b45309" },
      error: { main: dark ? "#ef4444" : "#b91c1c" },
      divider: dark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.08)",
      text: dark
        ? { primary: "#e6e8ee", secondary: "rgba(230,232,238,0.65)" }
        : { primary: "#0f172a", secondary: "rgba(15,23,42,0.65)" },
    },
    shape: baseShape,
    typography: { ...baseTypography, fontSize },
    components: sharedComponents(mode),
  });
}

export const connectionColor = (
  name: string,
): "success" | "info" | "warning" | "default" => {
  switch (name) {
    case "default":
      return "success";
    case "corp":
      return "info";
    case "bypass":
      return "warning";
    default:
      return "default";
  }
};
