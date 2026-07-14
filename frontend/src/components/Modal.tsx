import type { ReactNode } from "react";

interface ModalProps {
  children: ReactNode;
  "aria-label": string;
  "data-testid"?: string;
}

export function Modal({ children, "aria-label": ariaLabel, "data-testid": testId }: ModalProps) {
  return (
    <div role="dialog" aria-modal="true" aria-label={ariaLabel} data-testid={testId} className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded border border-carbon-700 bg-carbon-900 p-6 shadow-xl">{children}</div>
    </div>
  );
}
