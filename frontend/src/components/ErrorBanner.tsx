/**
 * ErrorBanner: ApiError-aware inline panel error (audit UI_UX #3).
 *
 * Pages currently re-implement the same `role="alert"` error paragraph
 * per-query (see `DevicesPage.tsx`'s `error.message` renders). This
 * component is the shared version: when the caught value is the RFC 7807
 * {@link ApiError} from `src/api/client.ts`, it renders the backend's
 * `problem.detail`; otherwise the component preserves its legacy plain-Error
 * behavior. The exported action formatter is safer by default: non-API errors
 * become generic copy unless a caller explicitly opts into an old page's
 * user-visible message contract.
 */

import { ApiError } from "../api/client";

interface ErrorBannerProps {
  error: unknown;
  "data-testid"?: string;
}

const ACTION_GENERIC_MESSAGE = "Something went wrong. Please try again.";
const BANNER_GENERIC_MESSAGE = "Something went wrong.";

interface MessageOptions {
  /** Preserve pages that intentionally rendered `ApiError.message` (title + detail). */
  includeProblemTitle?: boolean;
  /** Opt in only where a pre-existing page intentionally exposed plain Error text. */
  exposeErrorMessage?: boolean;
  /** Context-specific fallback for non-Error throws. */
  fallback?: string;
}

/** Resolve the best available message for an unknown thrown/caught value. */
// eslint-disable-next-line react-refresh/only-export-components -- requirement: ErrorBanner.messageFor is the shared page formatter.
export function messageFor(error: unknown, options: MessageOptions = {}): string {
  const fallback = options.fallback ?? ACTION_GENERIC_MESSAGE;
  if (error instanceof ApiError) {
    if (options.includeProblemTitle && error.problem.detail) {
      return error.message;
    }
    return error.problem.detail || fallback;
  }
  if (options.exposeErrorMessage && error instanceof Error) {
    return error.message || fallback;
  }
  return fallback;
}

export function ErrorBanner({ error, "data-testid": dataTestId }: ErrorBannerProps) {
  return (
    <div
      role="alert"
      data-testid={dataTestId}
      className="panel border-status-error/40 px-4 py-3 text-xs text-status-error"
    >
      {messageFor(error, {
        exposeErrorMessage: true,
        fallback: BANNER_GENERIC_MESSAGE,
      })}
    </div>
  );
}
