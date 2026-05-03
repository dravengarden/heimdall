import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { CssBaseline, ThemeProvider } from "@mui/material";
import { App } from "./App";
import { I18nProvider } from "./i18n";
import { useThemeMode } from "./hooks/useThemeMode";

function Root() {
  const tm = useThemeMode();
  return (
    <ThemeProvider theme={tm.theme}>
      <CssBaseline />
      <App
        themeMode={tm.mode}
        onThemeModeChange={tm.setMode}
        fontSize={tm.fontSize}
        onFontSizeChange={tm.setFontSize}
      />
    </ThemeProvider>
  );
}

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("root element missing");

createRoot(rootEl).render(
  <StrictMode>
    <I18nProvider>
      <Root />
    </I18nProvider>
  </StrictMode>,
);
