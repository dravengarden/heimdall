import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Box } from "@mui/material";
import { useKbState } from "./KeybindingsProvider";

// Vimium-style link-hint mode.
//
// Mounts a fixed-position overlay over every DOM element marked with
// `data-vim-hint`, generates short labels (Vimium algorithm — home-row
// preference, 1-char for the most reachable letters then 2-char), and
// listens for keystrokes. Type a label → fire that element's `click()`
// or focus it (depending on its `data-vim-hint-action`). Any non-match
// cancels. Esc cancels.
//
// Why not call into the page's existing keymap: hint mode owns the
// keystream while it's open. The provider's main listener bails when
// `hintActive` is true, so we never double-dispatch.

const ALPHABET = "asdfghjkl;"; // home row, US layout

export interface HintTarget {
  el: HTMLElement;
  rect: DOMRect;
  action: () => void;
}

export function HintMode() {
  const { hintActive, setHintActive } = useKbState();
  const [typed, setTyped] = useState("");
  const [targets, setTargets] = useState<HintTarget[]>([]);
  const [labels, setLabels] = useState<readonly string[]>([]);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Recompute targets on entering hint mode and on scroll/resize while
  // active — the DataGrid virtualises rows so the visible set shifts.
  useEffect(() => {
    if (!hintActive) {
      setTargets([]);
      setLabels([]);
      setTyped("");
      return;
    }

    function collect() {
      const els = Array.from(
        document.querySelectorAll<HTMLElement>("[data-vim-hint]"),
      );
      const visible: HintTarget[] = [];
      for (const el of els) {
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) continue;
        if (
          rect.bottom < 0 ||
          rect.right < 0 ||
          rect.top > window.innerHeight ||
          rect.left > window.innerWidth
        )
          continue;
        const action = () => {
          // Default: click. `data-vim-hint-action="focus"` opts into
          // focusing instead — useful for inputs.
          if (el.getAttribute("data-vim-hint-action") === "focus") {
            el.focus();
          } else {
            el.click();
          }
        };
        visible.push({ el, rect, action });
      }
      setTargets(visible);
      setLabels(allocateLabels(visible.length));
    }

    collect();
    const onScroll = () => requestAnimationFrame(collect);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onScroll);
    };
  }, [hintActive]);

  // Keystroke listener — owns input while active.
  useEffect(() => {
    if (!hintActive) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        setHintActive(false);
        return;
      }
      if (e.key.length !== 1) return;
      const ch = e.key.toLowerCase();
      if (!ALPHABET.includes(ch)) return;
      e.preventDefault();
      e.stopPropagation();
      const next = typed + ch;
      // Exact match → fire and exit.
      const idx = labels.indexOf(next);
      if (idx >= 0) {
        const t = targets[idx];
        // Defer the click so this listener has fully unwound — some
        // targets (DataGrid rows) re-render on click and would double-
        // fire the overlay otherwise.
        window.setTimeout(() => t?.action(), 0);
        setHintActive(false);
        return;
      }
      // Prefix match → keep going.
      const stillPossible = labels.some((lbl) => lbl.startsWith(next));
      if (stillPossible) {
        setTyped(next);
      } else {
        // Dead end — drop and reset.
        setTyped("");
      }
    }
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [hintActive, typed, labels, targets, setHintActive]);

  if (!hintActive) return null;
  if (targets.length === 0) return null;

  const overlay = (
    <Box
      ref={containerRef}
      sx={{
        position: "fixed",
        inset: 0,
        pointerEvents: "none",
        zIndex: (t) => t.zIndex.tooltip + 2,
      }}
    >
      {targets.map((t, i) => {
        const lbl = labels[i] ?? "";
        const matched = typed.length > 0 && lbl.startsWith(typed);
        if (typed.length > 0 && !matched) return null;
        return (
          <Box
            key={i}
            sx={{
              position: "absolute",
              left: t.rect.left + window.scrollX,
              top: t.rect.top + window.scrollY,
              transform: "translate(-2px, -2px)",
              fontFamily: "monospace",
              fontSize: 11,
              fontWeight: 700,
              color: "common.black",
              bgcolor: "warning.main",
              border: 1,
              borderColor: "warning.dark",
              borderRadius: 0.5,
              px: 0.5,
              py: 0.1,
              lineHeight: 1.1,
              boxShadow: 1,
            }}
          >
            <Box component="span" sx={{ opacity: 0.5 }}>
              {lbl.slice(0, typed.length)}
            </Box>
            <Box component="span">{lbl.slice(typed.length)}</Box>
          </Box>
        );
      })}
    </Box>
  );

  return createPortal(overlay, document.body);
}

// Allocate labels for N targets using the Vimium algorithm.
// 1-char labels for the first batch (count = A − ⌈N/A⌉ when N > A),
// 2-char labels for the rest. Letters are drawn from ALPHABET in order.
export function allocateLabels(n: number): readonly string[] {
  if (n <= 0) return [];
  const a = ALPHABET.length;
  if (n <= a) {
    return Array.from({ length: n }, (_, i) => ALPHABET[i]!);
  }
  // How many 1-char labels can we afford while still labelling
  // every remaining target with a 2-char chord whose first char is
  // distinct from any used 1-char?
  const oneCharCount = Math.max(0, a - Math.ceil(n / a));
  const labels: string[] = [];
  for (let i = 0; i < oneCharCount; i++) labels.push(ALPHABET[i]!);
  const remaining = n - oneCharCount;
  // Use the rest of ALPHABET as the prefix half of 2-char labels.
  outer: for (let p = oneCharCount; p < a; p++) {
    for (let q = 0; q < a; q++) {
      labels.push(ALPHABET[p]! + ALPHABET[q]!);
      if (labels.length >= n) break outer;
    }
    if (labels.length >= n) break;
    void remaining;
  }
  return labels;
}
