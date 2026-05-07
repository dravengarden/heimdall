import { useEffect } from "react";
import { useKbState } from "./KeybindingsProvider";

// `?` and `f` need access to KbContext (helpOpen / hintActive setters),
// but the provider is built before its consumers exist — there's no
// way to thread these through the App's `handlers` prop without a
// circular dependency. So this tiny bridge sits inside the provider
// tree, subscribes to the global keystream itself, and toggles the
// state when those keys fire.
//
// We re-implement the same input-suppression check as the provider so
// nothing fires while the user is typing.
export function KbHandlersBridge() {
  const { setHelpOpen, setHintActive, hintActive } = useKbState();

  useEffect(() => {
    function isEditable(el: EventTarget | null): boolean {
      const t = el as HTMLElement | null;
      return (
        t instanceof HTMLInputElement ||
        t instanceof HTMLTextAreaElement ||
        t?.isContentEditable === true
      );
    }
    function onKeyDown(e: KeyboardEvent) {
      if (isEditable(e.target)) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (hintActive) return;

      if (e.key === "?" || (e.key === "/" && e.shiftKey)) {
        // Shift+/ → "?". Some layouts emit "?" directly, others need
        // shift inspection. Either is fine.
        e.preventDefault();
        setHelpOpen(true);
        return;
      }
      if (e.key === "f") {
        // The provider also has `hint.enter` mapped to "f", but routes
        // through `handlers[id]?.()` which is no-op since we don't
        // populate that id from App.tsx (it'd need access to context).
        // We handle it here — single source of truth for entering hint
        // mode is this bridge.
        e.preventDefault();
        setHintActive(true);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [setHelpOpen, setHintActive, hintActive]);

  return null;
}
