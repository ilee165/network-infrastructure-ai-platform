/**
 * Toaster: portal-rendered toast stack (audit UI_UX #6).
 *
 * Reads the `toasts` array from the shared `ui.ts` store and renders it as a
 * fixed bottom-right stack via `createPortal`, so a long-running async
 * outcome (discovery run finished, config deploy failed, CR approved) is
 * visible regardless of which page the user is currently on. Auto-dismiss
 * timers live here (not in the store) so `pushToast`/`dismissToast` stay pure
 * and independently testable; each toast's timer is cleared on manual
 * dismiss and on unmount.
 */

import { useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import { StatusPill, type StatusPillVariant } from "./StatusPill";
import { useUiStore, type Toast, type ToastKind } from "../stores/ui";

/** Auto-dismiss delay per toast kind (ms); errors linger longer. */
const AUTO_DISMISS_MS: Record<ToastKind, number> = {
  success: 5_000,
  error: 8_000,
  info: 5_000,
};

/** Map a toast's semantic kind onto the sanctioned StatusPill tone/label. */
const TOAST_PILL: Record<ToastKind, { variant: StatusPillVariant; label: string }> = {
  success: { variant: "ok", label: "Success" },
  error: { variant: "error", label: "Error" },
  info: { variant: "neutral", label: "Info" },
};

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: string) => void }) {
  const { variant, label } = TOAST_PILL[toast.kind];
  return (
    <div className="panel flex items-start gap-3 border-carbon-700 px-3 py-2 shadow-lg transition-opacity motion-reduce:transition-none">
      <StatusPill variant={variant}>{label}</StatusPill>
      <p className="min-w-0 flex-1 break-words text-xs text-zinc-200">{toast.message}</p>
      <button
        type="button"
        aria-label="Dismiss notification"
        onClick={() => onDismiss(toast.id)}
        className="shrink-0 text-xs text-zinc-500 transition-colors hover:text-zinc-200 motion-reduce:transition-none"
      >
        ✕
      </button>
    </div>
  );
}

export function Toaster() {
  const toasts = useUiStore((state) => state.toasts);
  const dismissToast = useUiStore((state) => state.dismissToast);
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());

  useEffect(() => {
    const active = timers.current;

    for (const toast of toasts) {
      if (!active.has(toast.id)) {
        const handle = setTimeout(() => {
          dismissToast(toast.id);
          active.delete(toast.id);
        }, AUTO_DISMISS_MS[toast.kind]);
        active.set(toast.id, handle);
      }
    }

    // A toast dismissed manually (or otherwise removed) no longer needs its timer.
    for (const [id, handle] of active) {
      if (!toasts.some((toast) => toast.id === id)) {
        clearTimeout(handle);
        active.delete(id);
      }
    }
  }, [toasts, dismissToast]);

  // Clear every outstanding timer on unmount.
  useEffect(() => {
    const active = timers.current;
    return () => {
      for (const handle of active.values()) {
        clearTimeout(handle);
      }
      active.clear();
    };
  }, []);

  if (toasts.length === 0) {
    return null;
  }

  return createPortal(
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2"
    >
      {toasts.map((toast) => (
        <ToastItem key={toast.id} toast={toast} onDismiss={dismissToast} />
      ))}
    </div>,
    document.body,
  );
}
