import { useEffect, type RefObject } from "react";

interface Args {
  searchInputRef: RefObject<HTMLInputElement | null>;
  selectedId: number | null;
  setSelectedId: (id: number | null) => void;
}

/**
 * Page-level keybinds, mitmweb-flavoured:
 *   /   focus search
 *   ESC clear selection / blur
 *   ?   placeholder for help (future)
 *
 * No bindings fire while a text input is focused, except ESC, which
 * blurs the focused element instead.
 */
export function useKeyboardShortcuts({
  searchInputRef,
  selectedId,
  setSelectedId,
}: Args): void {
  useEffect(() => {
    const handler = (e: KeyboardEvent): void => {
      const target = e.target as HTMLElement | null;
      const inEditable =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target?.isContentEditable === true;

      if (e.key === "Escape") {
        if (inEditable && target) {
          target.blur();
        } else if (selectedId != null) {
          setSelectedId(null);
        }
        return;
      }

      if (inEditable) return;

      if (e.key === "/") {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [searchInputRef, selectedId, setSelectedId]);
}
