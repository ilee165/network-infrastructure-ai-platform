/**
 * ErrorBanner: ApiError-aware inline panel error (audit UI_UX #3).
 *
 * Pages currently re-implement the same `role="alert"` error paragraph
 * per-query (see `DevicesPage.tsx`'s `error.message` renders). This
 * component is the shared version: when the caught value is the RFC 7807
 * {@link ApiError} from `src/api/client.ts`, it renders the backend's
 * `problem.detail`; otherwise it falls back to `error.message` (for a plain
 * `Error`) or a generic message for any other thrown value.
 */

import { ApiError } from "../api/client";

interface ErrorBannerProps {
  error: unknown;
  "data-testid"?: string;
}

const GENERIC_MESSAGE = "Something went wrong.";

/** Resolve the best available message for an unknown thrown/caught value. */
function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    return error.problem.detail;
  }
  if (error instanceof Error) {
    return error.message || GENERIC_MESSAGE;
  }
  return GENERIC_MESSAGE;
}

export function ErrorBanner({ error, "data-testid": dataTestId }: ErrorBannerProps) {
  return (
    <div
      role="alert"
      data-testid={dataTestId}
      className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
    >
      {messageFor(error)}
    </div>
  );
}
