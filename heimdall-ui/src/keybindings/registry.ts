// Central registry of every keybinding in heimdall-ui.
//
// Read by:
//   - KeybindingsProvider          → registers handlers with react-hotkeys-hook
//   - WhichKeyPopup                → renders next-key continuations after a prefix
//   - HelpOverlay                  → renders the full `?` reference grid
//   - StatusChip                   → renders pending-prefix label
//
// Adding a binding here is the only place you should need to edit; the
// popup / overlay / status indicator all derive from this list.

export type Scope = "global" | "table" | "drawer" | "livetap" | "hint";

/** Logical name of a handler — the provider supplies the actual function. */
export type ActionId =
  // Navigation in the active panel
  | "nav.down"
  | "nav.up"
  | "nav.top"
  | "nav.bottom"
  | "nav.halfDown"
  | "nav.halfUp"
  // Open / close
  | "flow.open"
  | "flow.close"
  | "flow.next"
  | "flow.prev"
  | "drawer.tabNext"
  // Yank
  | "yank.id"
  | "yank.curl"
  | "yank.host"
  // View navigation
  | "goto.table"
  | "goto.livetap"
  | "goto.filter"
  | "goto.settings"
  | "goto.drawer"
  // Filter
  | "filter.focus"
  | "filter.clear"
  | "filter.refresh"
  // Live tap
  | "tap.toggleFollow"
  | "tap.jumpTail"
  | "tap.clear"
  // UI toggles
  | "ui.toggleDark"
  | "ui.toggleTap"
  // Modes
  | "hint.enter"
  | "hint.cancel"
  | "help.toggle"
  | "esc.hierarchy";

export interface Binding {
  /** Stable id consumed by the provider's handler map. */
  readonly id: ActionId;
  /** react-hotkeys-hook key syntax. `>` is sequence separator. */
  readonly keys: string;
  /** Where this binding fires. `global` always fires regardless. */
  readonly scope: Scope;
  /** Group label for the help overlay + which-key popup. */
  readonly group:
    | "navigation"
    | "goto"
    | "filter"
    | "flow"
    | "yank"
    | "ui"
    | "tap"
    | "mode";
  /** Human-readable description. Single short sentence. */
  readonly desc: string;
  /**
   * When set, this binding is treated as a chord-prefix root in the
   * which-key popup — pressing this key starts a 250ms timer that
   * shows continuations whose `keys` start with the same prefix.
   * Only relevant for single-key roots like `g`, `s`, `u`, `y`.
   */
  readonly prefixRoot?: string;
}

export const BINDINGS: readonly Binding[] = [
  // ── Global single-key ─────────────────────────────────────────────
  { id: "help.toggle",   keys: "?",      scope: "global",  group: "mode",
    desc: "Toggle help overlay" },
  { id: "esc.hierarchy", keys: "escape", scope: "global",  group: "mode",
    desc: "Back out / cancel" },
  { id: "filter.focus",  keys: "/",      scope: "global",  group: "filter",
    desc: "Focus filter bar" },
  { id: "hint.enter",    keys: "f",      scope: "global",  group: "mode",
    desc: "Hint mode — type label to click" },

  // ── Global chord prefixes (`g x`, `s x`, `u x`, `y x`) ────────────
  { id: "goto.table",    keys: "g>t",    scope: "global",  group: "goto",
    desc: "Go to flow table",       prefixRoot: "g" },
  { id: "goto.livetap",  keys: "g>l",    scope: "global",  group: "goto",
    desc: "Go to live tap",         prefixRoot: "g" },
  { id: "goto.filter",   keys: "g>f",    scope: "global",  group: "goto",
    desc: "Focus filter bar",       prefixRoot: "g" },
  { id: "goto.settings", keys: "g>s",    scope: "global",  group: "goto",
    desc: "Open settings drawer",   prefixRoot: "g" },
  { id: "goto.drawer",   keys: "g>d",    scope: "global",  group: "goto",
    desc: "Open detail drawer (selected flow)", prefixRoot: "g" },

  { id: "ui.toggleDark", keys: "u>d",    scope: "global",  group: "ui",
    desc: "Toggle dark mode",       prefixRoot: "u" },
  { id: "ui.toggleTap",  keys: "u>t",    scope: "global",  group: "ui",
    desc: "Toggle tap follow",      prefixRoot: "u" },

  { id: "yank.id",       keys: "y>i",    scope: "global",  group: "yank",
    desc: "Yank flow ID",           prefixRoot: "y" },
  { id: "yank.curl",     keys: "y>c",    scope: "global",  group: "yank",
    desc: "Yank flow as curl",      prefixRoot: "y" },
  { id: "yank.host",     keys: "y>h",    scope: "global",  group: "yank",
    desc: "Yank dst hostname",      prefixRoot: "y" },

  // ── Flow table scope ──────────────────────────────────────────────
  { id: "nav.down",      keys: "j",      scope: "table",   group: "navigation",
    desc: "Next row" },
  { id: "nav.up",        keys: "k",      scope: "table",   group: "navigation",
    desc: "Previous row" },
  { id: "nav.top",       keys: "g>g",    scope: "table",   group: "navigation",
    desc: "First row",              prefixRoot: "g" },
  { id: "nav.bottom",    keys: "shift+g",scope: "table",   group: "navigation",
    desc: "Last row" },
  { id: "nav.halfDown",  keys: "ctrl+d", scope: "table",   group: "navigation",
    desc: "Half-page down" },
  { id: "nav.halfUp",    keys: "ctrl+u", scope: "table",   group: "navigation",
    desc: "Half-page up" },
  { id: "flow.open",     keys: "enter, l, o", scope: "table", group: "flow",
    desc: "Open detail drawer" },
  { id: "filter.refresh",keys: "r",      scope: "table",   group: "filter",
    desc: "Refresh flows" },
  { id: "filter.clear",  keys: "c",      scope: "table",   group: "filter",
    desc: "Clear all filters" },

  // ── Detail drawer scope ───────────────────────────────────────────
  { id: "flow.close",    keys: "h, escape", scope: "drawer", group: "flow",
    desc: "Close drawer" },
  { id: "flow.next",     keys: "shift+j", scope: "drawer",  group: "flow",
    desc: "Next flow" },
  { id: "flow.prev",     keys: "shift+k", scope: "drawer",  group: "flow",
    desc: "Previous flow" },
  { id: "drawer.tabNext",keys: "tab",    scope: "drawer",  group: "navigation",
    desc: "Cycle drawer sub-tabs" },

  // ── Live tap scope ────────────────────────────────────────────────
  { id: "tap.toggleFollow", keys: "f",   scope: "livetap", group: "tap",
    desc: "Toggle follow tail" },
  { id: "tap.jumpTail",  keys: "shift+g",scope: "livetap", group: "tap",
    desc: "Jump to tail" },
  { id: "tap.clear",     keys: "c",      scope: "livetap", group: "tap",
    desc: "Clear buffer" },
];

/**
 * All distinct chord prefixes (single keys like `g`, `s`, …) that should
 * trigger the which-key popup after the configured delay.
 */
export const PREFIX_ROOTS: readonly string[] = Array.from(
  new Set(BINDINGS.flatMap((b) => (b.prefixRoot ? [b.prefixRoot] : []))),
);

/**
 * Continuations for a given prefix root, in the active scope set.
 * Used by the which-key popup.
 */
export function continuationsFor(
  prefix: string,
  activeScopes: ReadonlySet<Scope>,
): readonly Binding[] {
  const head = prefix + ">";
  return BINDINGS.filter(
    (b) =>
      b.keys.startsWith(head) &&
      (b.scope === "global" || activeScopes.has(b.scope)),
  );
}

/** Render the second key of a chord (`g>t` → `t`). */
export function chordTail(b: Binding): string {
  const idx = b.keys.indexOf(">");
  return idx >= 0 ? b.keys.slice(idx + 1) : b.keys;
}
