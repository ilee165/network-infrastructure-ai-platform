import { Modal } from "./Modal";

interface ConfirmDialogProps {
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
  isPending?: boolean;
  error?: string | null;
  confirmLabel?: string;
  pendingLabel?: string;
  confirmTestId?: string;
}

export function ConfirmDialog({ message, onConfirm, onCancel, isPending, error, confirmLabel = "Confirm", pendingLabel = "Working…", confirmTestId }: ConfirmDialogProps) {
  return <Modal aria-label="Confirm action">
    <p className="text-sm text-zinc-200">{message}</p>
    {error ? <p role="alert" className="mt-3 text-xs text-status-error">{error}</p> : null}
    <div className="mt-5 flex justify-end gap-3">
      <button type="button" onClick={onCancel} disabled={isPending} className="rounded border border-carbon-700 px-3 py-1.5 text-xs text-zinc-400 transition-colors hover:border-carbon-600 hover:text-zinc-100 disabled:opacity-60">Cancel</button>
      <button type="button" data-testid={confirmTestId} onClick={onConfirm} disabled={isPending} className="rounded bg-status-error px-3 py-1.5 text-xs font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-60">{isPending ? pendingLabel : confirmLabel}</button>
    </div>
  </Modal>;
}
