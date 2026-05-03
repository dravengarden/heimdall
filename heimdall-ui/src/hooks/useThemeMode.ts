import { useEffect, useMemo, useState } from "react";
import { useMediaQuery } from "@mui/material";
import { buildTheme, type ThemeMode } from "../theme";

const STORAGE_KEY = "heimdall.themeMode";
const FONT_KEY = "heimdall.fontSize";
const FONT_DEFAULT = 13;
const FONT_MIN = 11;
const FONT_MAX = 16;

interface UseThemeMode {
  mode: ThemeMode;
  resolved: "light" | "dark";
  fontSize: number;
  setMode: (m: ThemeMode) => void;
  setFontSize: (px: number) => void;
  theme: ReturnType<typeof buildTheme>;
}

function readMode(): ThemeMode {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark" || v === "auto") return v;
  } catch {
    /* ignore */
  }
  return "auto";
}

function readFont(): number {
  try {
    const v = Number(localStorage.getItem(FONT_KEY));
    if (Number.isFinite(v) && v >= FONT_MIN && v <= FONT_MAX) return v;
  } catch {
    /* ignore */
  }
  return FONT_DEFAULT;
}

export function useThemeMode(): UseThemeMode {
  const [mode, setModeState] = useState<ThemeMode>(readMode);
  const [fontSize, setFontSizeState] = useState<number>(readFont);
  const prefersDark = useMediaQuery("(prefers-color-scheme: dark)", {
    noSsr: true,
  });

  const resolved: "light" | "dark" =
    mode === "auto" ? (prefersDark ? "dark" : "light") : mode;

  // Update <meta name="theme-color"> + <html data-theme> for nice OS chrome.
  useEffect(() => {
    document.documentElement.dataset["theme"] = resolved;
    const meta = document.querySelector(
      'meta[name="theme-color"]',
    ) as HTMLMetaElement | null;
    if (meta) meta.content = resolved === "dark" ? "#0f172a" : "#ffffff";
    document.body.style.background = resolved === "dark" ? "#0a0e1a" : "#f5f6fa";
    document.body.style.color = resolved === "dark" ? "#e6e8ee" : "#0f172a";
  }, [resolved]);

  const setMode = (m: ThemeMode): void => {
    setModeState(m);
    try {
      localStorage.setItem(STORAGE_KEY, m);
    } catch {
      /* ignore */
    }
  };

  const setFontSize = (px: number): void => {
    const clamped = Math.min(FONT_MAX, Math.max(FONT_MIN, Math.round(px)));
    setFontSizeState(clamped);
    try {
      localStorage.setItem(FONT_KEY, String(clamped));
    } catch {
      /* ignore */
    }
  };

  const theme = useMemo(
    () => buildTheme(resolved, fontSize),
    [resolved, fontSize],
  );

  return { mode, resolved, fontSize, setMode, setFontSize, theme };
}

export const FONT_SIZE_BOUNDS = {
  min: FONT_MIN,
  max: FONT_MAX,
  default: FONT_DEFAULT,
} as const;
