import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
  type RefObject,
} from "react";
import {
  BINDINGS,
  PREFIX_ROOTS,
  type ActionId,
  type Binding,
  type Scope,
} from "./registry";

// ─── State surface ────────────────────────────────────────────────────
//
// The provider owns three piece of UI state that the popup / status /
// hint mode subscribe to. Everything else (selected flow, view, filters,
// settings) stays in App.tsx — the provider only routes keys to the
// callbacks the App supplies.

export interface KbState {
  /** Currently held chord prefix (e.g. "g") or null. */
  pendingPrefix: string | null;
  /** Active scopes — global plus whatever the App requested. */
  activeScopes: ReadonlySet<Scope>;
  /** Whether the help overlay is open. */
  helpOpen: boolean;
  /** Whether hint mode is active. */
  hintActive: boolean;
}

export interface KbApi extends KbState {
  setHelpOpen: (open: boolean) => void;
  setHintActive: (active: boolean) => void;
  /** Walk Esc hierarchy — provider decides what closes first. */
  escHierarchy: () => void;
}

const KbContext = createContext<KbApi | null>(null);

export function useKbState(): KbApi {
  const v = useContext(KbContext);
  if (!v) throw new Error("useKbState() outside KeybindingsProvider");
  return v;
}

// ─── Handlers — supplied by the App at mount ──────────────────────────
//
// The App glues these to its setState callbacks. Missing entries are
// silently no-ops, so the registry can list bindings the App hasn't
// wired yet. Adding a real handler is the only place the App knows
// about a specific binding's id.

export type Handlers = Partial<Record<ActionId, () => void>>;

export interface KeybindingsProviderProps {
  handlers: Handlers;
  /** Scopes the App enables on top of `global`. */
  scopes: ReadonlyArray<Scope>;
  children: ReactNode;
}

export function KeybindingsProvider({
  handlers,
  scopes,
  children,
}: KeybindingsProviderProps) {
  const [pendingPrefix, setPendingPrefix] = useState<string | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [hintActive, setHintActive] = useState(false);

  // Stable timer ref so re-renders don't drop in-flight prefix arm.
  const prefixTimer = useRef<number | null>(null);
  const idleTimer = useRef<number | null>(null);

  const activeScopes = useMemo<ReadonlySet<Scope>>(
    () => new Set<Scope>(["global", ...scopes]),
    [scopes],
  );

  const clearPrefix = useCallback(() => {
    setPendingPrefix(null);
    if (prefixTimer.current) {
      window.clearTimeout(prefixTimer.current);
      prefixTimer.current = null;
    }
    if (idleTimer.current) {
      window.clearTimeout(idleTimer.current);
      idleTimer.current = null;
    }
  }, []);

  // ── Esc hierarchy ──────────────────────────────────────────────────
  // Order: pending prefix → hint mode → focused input → help overlay
  //        → caller-supplied (App closes drawer/settings/clears selection).
  const escHierarchy = useCallback(() => {
    if (pendingPrefix) {
      clearPrefix();
      return;
    }
    if (hintActive) {
      setHintActive(false);
      return;
    }
    const active = document.activeElement as HTMLElement | null;
    const editable =
      active instanceof HTMLInputElement ||
      active instanceof HTMLTextAreaElement ||
      active?.isContentEditable === true;
    if (editable) {
      active?.blur();
      return;
    }
    if (helpOpen) {
      setHelpOpen(false);
      return;
    }
    handlers["esc.hierarchy"]?.();
  }, [pendingPrefix, hintActive, helpOpen, handlers, clearPrefix]);

  // ── Single global keydown listener ────────────────────────────────
  //
  // One listener for the whole app. Reasons over react-hotkeys-hook
  // here:
  //   - registry has ~30 bindings; calling useHotkeys per binding hits
  //     rules-of-hooks issues if the list is iterated.
  //   - chord-prefix popup needs precise timer control (250 ms show,
  //     1500 ms idle clear) which is awkward to model with the lib.
  //   - the lib's `enableOnFormTags=false` is a single check we can
  //     replicate in five lines.
  useEffect(() => {
    function isEditable(el: EventTarget | null): boolean {
      const t = el as HTMLElement | null;
      return (
        t instanceof HTMLInputElement ||
        t instanceof HTMLTextAreaElement ||
        t?.isContentEditable === true
      );
    }

    function eventKey(e: KeyboardEvent): string {
      // Render the event into a key-string the registry can match.
      // `Ctrl+d`, `Shift+G`, `escape`, `tab`, plain `j`, etc. We
      // lowercase printable keys so the registry doesn't have to
      // care about caps-lock state, but keep `Shift+G` / `Shift+J`
      // as their own bindings (Shift-plus-letter is a deliberate
      // separate chord).
      const parts: string[] = [];
      if (e.ctrlKey) parts.push("ctrl");
      if (e.metaKey) parts.push("meta");
      if (e.altKey) parts.push("alt");
      const k = e.key;
      if (e.shiftKey && k.length === 1) parts.push("shift");
      const base =
        k === " " ? "space" :
        k === "Escape" ? "escape" :
        k === "Tab" ? "tab" :
        k === "Enter" ? "enter" :
        k.length === 1 ? k.toLowerCase() :
        k.toLowerCase();
      parts.push(base);
      return parts.join("+");
    }

    function matchesBinding(b: Binding, ev: string): boolean {
      // Binding.keys may be a comma-separated alias list (`enter, l, o`)
      // or a chord (`g>t`). We split on commas into alternatives, and
      // each alternative must match either as bare key or chord-tail
      // when a prefix is pending.
      const alts = b.keys.split(",").map((s) => s.trim());
      for (const alt of alts) {
        if (alt.includes(">")) continue; // chord — handled below
        if (alt === ev) return true;
      }
      return false;
    }

    function matchesChord(b: Binding, prefix: string, ev: string): boolean {
      const want = `${prefix}>${ev}`;
      const alts = b.keys.split(",").map((s) => s.trim());
      return alts.includes(want);
    }

    function onKeyDown(e: KeyboardEvent) {
      const editable = isEditable(e.target);
      const ev = eventKey(e);

      // Esc always works — even inside inputs (blurs them via the
      // hierarchy callback).
      if (ev === "escape") {
        e.preventDefault();
        escHierarchy();
        return;
      }

      // Inside a text input, vim bindings yield to the user's typing.
      if (editable) return;

      // Hint mode owns the keystream until it exits — its own listener
      // handles label-typing; we just ignore everything else here.
      if (hintActive) return;

      // ── Chord-tail dispatch ──────────────────────────────────────
      if (pendingPrefix) {
        for (const b of BINDINGS) {
          if (b.scope !== "global" && !activeScopes.has(b.scope)) continue;
          if (matchesChord(b, pendingPrefix, ev)) {
            e.preventDefault();
            clearPrefix();
            handlers[b.id]?.();
            return;
          }
        }
        // Unknown chord tail → cancel prefix, fall through to bare match.
        clearPrefix();
      }

      // ── Bare-key dispatch ────────────────────────────────────────
      // Special case: `?` and `/` etc. don't go through `Shift` modeling.
      // The eventKey() function already strips Shift for bare-letter
      // bindings handled here as the lowercase base.
      for (const b of BINDINGS) {
        if (b.scope !== "global" && !activeScopes.has(b.scope)) continue;
        if (matchesBinding(b, ev)) {
          e.preventDefault();
          handlers[b.id]?.();
          return;
        }
      }

      // ── Prefix-root arm ─────────────────────────────────────────
      // No binding matched as bare; if it's a known root, arm the
      // pending state and start the popup timer.
      const isRoot = ev.length === 1 && PREFIX_ROOTS.includes(ev);
      if (isRoot) {
        e.preventDefault();
        setPendingPrefix(ev);
        if (prefixTimer.current) window.clearTimeout(prefixTimer.current);
        // Popup itself is purely state-driven; the 250ms delay is
        // implemented by the popup component reading `pendingPrefix`
        // via context and applying its own showAfter logic.
        if (idleTimer.current) window.clearTimeout(idleTimer.current);
        idleTimer.current = window.setTimeout(() => {
          setPendingPrefix((cur) => (cur === ev ? null : cur));
        }, 1500);
      }
    }

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [
    activeScopes,
    handlers,
    pendingPrefix,
    hintActive,
    clearPrefix,
    escHierarchy,
  ]);

  const api = useMemo<KbApi>(
    () => ({
      pendingPrefix,
      activeScopes,
      helpOpen,
      hintActive,
      setHelpOpen,
      setHintActive,
      escHierarchy,
    }),
    [pendingPrefix, activeScopes, helpOpen, hintActive, escHierarchy],
  );

  return <KbContext.Provider value={api}>{children}</KbContext.Provider>;
}

// ─── Tiny helper for App.tsx — focus a ref from a handler. ────────────

export function useFocusRef(ref: RefObject<HTMLElement | null>): () => void {
  return useCallback(() => {
    ref.current?.focus();
  }, [ref]);
}
