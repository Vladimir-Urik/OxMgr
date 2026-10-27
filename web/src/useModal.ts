import { useEffect, useRef, type RefObject } from "react";

const FOCUSABLE =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Open modals, innermost last: only the top one reacts to Escape and Tab. */
const stack: object[] = [];

export function isModalOpen(): boolean {
  return stack.length > 0;
}

/**
 * Modal behaviour for a dialog element: moves focus inside on open, keeps Tab
 * within it, closes the topmost modal on Escape and gives focus back to the
 * element that opened it.
 */
export function useModal(
  container: RefObject<HTMLElement | null>,
  onClose: () => void,
  options: { dismissible?: boolean; initialFocus?: RefObject<HTMLElement | null> } = {},
) {
  const latest = useRef({ onClose, dismissible: options.dismissible ?? true });
  latest.current = { onClose, dismissible: options.dismissible ?? true };
  const initialFocus = options.initialFocus;

  useEffect(() => {
    const token = {};
    stack.push(token);
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const first = initialFocus?.current ?? container.current?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();

    const onKey = (event: KeyboardEvent) => {
      if (stack[stack.length - 1] !== token) return;
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        if (latest.current.dismissible) latest.current.onClose();
        return;
      }
      if (event.key !== "Tab" || !container.current) return;
      const items = [...container.current.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (items.length === 0) return;
      const firstItem = items[0]!;
      const lastItem = items[items.length - 1]!;
      const active = document.activeElement;
      if (event.shiftKey && (active === firstItem || !container.current.contains(active))) {
        event.preventDefault();
        lastItem.focus();
      } else if (!event.shiftKey && (active === lastItem || !container.current.contains(active))) {
        event.preventDefault();
        firstItem.focus();
      }
    };
    document.addEventListener("keydown", onKey, true);

    return () => {
      document.removeEventListener("keydown", onKey, true);
      stack.splice(stack.indexOf(token), 1);
      opener?.focus();
    };
  }, [container, initialFocus]);
}
