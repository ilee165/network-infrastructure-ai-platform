/**
 * FormField: explicit label/control association (audit UI_UX #5).
 *
 * Login and Change Password currently rely on implicit association (an
 * `<input>` nested inside its `<label>`) with no `id`/`htmlFor` pair and no
 * wiring for validation errors. This component generates a stable id via
 * `useId` and hands it — plus `aria-invalid`/`aria-describedby` for the error
 * text — to the caller's control via a render-prop, which keeps the control's
 * own element type (input, select, textarea, …) fully type-checked instead of
 * relying on an untyped `cloneElement` cast.
 */

import { useId, type ReactNode } from "react";

/** Props the render-prop must spread onto its control element. */
export interface FormFieldControlProps {
  id: string;
  "aria-invalid"?: boolean;
  "aria-describedby"?: string;
}

interface FormFieldProps {
  label: string;
  /** Validation/error message; when present the control is marked invalid. */
  error?: string;
  required?: boolean;
  children: (controlProps: FormFieldControlProps) => ReactNode;
}

export function FormField({ label, error, required = false, children }: FormFieldProps) {
  const id = useId();
  const errorId = `${id}-error`;
  const hasError = Boolean(error);

  const controlProps: FormFieldControlProps = {
    id,
    ...(hasError ? { "aria-invalid": true, "aria-describedby": errorId } : {}),
  };

  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs text-zinc-400">
        {label}
        {required && (
          <span aria-hidden="true" className="ml-0.5 text-status-error">
            *
          </span>
        )}
      </label>
      {children(controlProps)}
      {hasError && (
        <p id={errorId} role="alert" className="text-xs text-status-error">
          {error}
        </p>
      )}
    </div>
  );
}
