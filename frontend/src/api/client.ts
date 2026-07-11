/**
 * Typed fetch wrapper for the NetOps API mounted at `/api/v1`.
 *
 * Error contract: the backend renders every failure as an RFC 7807
 * problem-details document (`application/problem+json`) — see
 * `backend/app/core/errors.py`. Non-2xx responses become {@link ApiError}
 * instances carrying that document; bodies that are not valid problem
 * documents (e.g. an HTML page from a proxy) are normalized into a synthetic
 * problem so callers always observe one error shape.
 *
 * Auth (Auth & Account UI, F1): every request injects the in-memory access
 * token from the auth store as `Authorization: Bearer <token>`. On a 401 the
 * client performs EXACTLY ONE silent `POST /auth/refresh` (the HttpOnly refresh
 * cookie travels automatically; no Authorization header is sent), then retries
 * the original request once with the freshly minted token. If the refresh fails
 * the store is set anonymous and the browser is redirected to `/login`. The
 * refresh call itself never triggers a nested refresh, and the original request
 * is retried at most once — there is no refresh loop. Concurrent 401s coalesce
 * onto a single in-flight refresh (single-flight guard): one POST, one new
 * token, every waiter retries with it; a failed refresh is not cached.
 */

import { useAuthStore } from "../stores/auth";

/** Versioned API prefix; the dev server proxies it to the FastAPI backend. */
export const API_BASE = "/api/v1";

/** Path (relative to {@link API_BASE}) of the silent token-refresh endpoint. */
export const REFRESH_PATH = "/auth/refresh";

/** Where an unrecoverable auth failure sends the browser. */
const LOGIN_PATH = "/login";

/** Default per-request timeout when the caller does not supply a signal (M34). */
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/**
 * Combine a caller-supplied signal with a default timeout so either abort
 * cancels the in-flight fetch. Falls back to the timeout alone when
 * `AbortSignal.any` is unavailable (older runtimes).
 */
function resolveSignal(caller?: AbortSignal | null): AbortSignal {
  const timeout = AbortSignal.timeout(DEFAULT_REQUEST_TIMEOUT_MS);
  if (caller == null) {
    return timeout;
  }
  const anyFactory = (
    AbortSignal as unknown as { any?: (signals: AbortSignal[]) => AbortSignal }
  ).any;
  if (typeof anyFactory === "function") {
    return anyFactory([caller, timeout]);
  }
  return caller;
}

/** Shape of the backend `{ access_token, token_type }` token responses. */
interface TokenResponse {
  access_token: string;
  token_type: string;
}

/** RFC 7807 problem-details document produced by the backend error handlers. */
export interface ProblemDetails {
  /** Stable error URN, e.g. `urn:netops:error:not-found`. */
  type: string;
  /** Human-readable summary, e.g. `Not Found`. */
  title: string;
  /** HTTP status code (mirrors the response status). */
  status: number;
  /** Instance-specific explanation; never contains secrets or stack traces. */
  detail: string;
  /** Request path that produced the error, when known. */
  instance?: string;
}

/** Error thrown for any non-2xx API response; wraps the problem document. */
export class ApiError extends Error {
  /** The (possibly synthesized) RFC 7807 document for this failure. */
  readonly problem: ProblemDetails;

  constructor(problem: ProblemDetails) {
    super(`${problem.title}: ${problem.detail}`);
    this.name = "ApiError";
    this.problem = problem;
  }

  /** HTTP status of the failed response. */
  get status(): number {
    return this.problem.status;
  }
}

function isProblemDetails(body: unknown): body is ProblemDetails {
  if (typeof body !== "object" || body === null) {
    return false;
  }
  const candidate = body as Record<string, unknown>;
  return (
    typeof candidate.type === "string" &&
    typeof candidate.title === "string" &&
    typeof candidate.status === "number" &&
    typeof candidate.detail === "string"
  );
}

async function toApiError(response: Response, path: string): Promise<ApiError> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined; // Non-JSON error body (proxy/HTML); fall through to synthesis.
  }
  if (isProblemDetails(body)) {
    return new ApiError(body);
  }
  return new ApiError({
    type: "about:blank",
    title: response.statusText || "Request Failed",
    status: response.status,
    detail: `Request to ${path} failed with HTTP ${response.status}.`,
    instance: path,
  });
}

/**
 * Issue a single request — base headers + optional Bearer — and return the raw
 * `Response`. No retry/refresh logic lives here; this is the one place the
 * network is touched so the refresh path can reuse it without recursing.
 */
async function rawFetch(
  path: string,
  init: RequestInit,
  options: { withAuth: boolean },
): Promise<Response> {
  const headers: Record<string, string> = {
    Accept: "application/json, application/problem+json",
    ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
    ...(init.headers as Record<string, string> | undefined),
  };
  if (options.withAuth) {
    const token = useAuthStore.getState().accessToken;
    if (token !== null) {
      headers.Authorization = `Bearer ${token}`;
    }
  }
  const signal = resolveSignal(init.signal ?? null);
  return fetch(`${API_BASE}${path}`, { ...init, headers, signal });
}

/** Parse a successful `Response` into `T` (`undefined` for 204). */
async function parse<T>(response: Response): Promise<T> {
  if (response.status === 204) {
    return undefined as unknown as T;
  }
  return (await response.json()) as T;
}

/**
 * The refresh currently in flight, if any. Concurrent 401s coalesce onto this
 * single promise (single-flight guard, audit FUNCTIONAL_BUGS #4): only ONE
 * `POST /auth/refresh` is issued no matter how many requests fail at once,
 * which also keeps parallel legitimate refreshes from tripping server-side
 * refresh-token reuse detection. Cleared in `finally` so a failed refresh is
 * never cached — the next 401 starts a brand-new attempt.
 */
let refreshInFlight: Promise<string | null> | null = null;

/**
 * Single-flight wrapper around {@link attemptRefresh}: all concurrent callers
 * await the same in-flight refresh and receive the same token (or `null`).
 */
function sharedRefresh(): Promise<string | null> {
  refreshInFlight ??= attemptRefresh().finally(() => {
    refreshInFlight = null;
  });
  return refreshInFlight;
}

/**
 * Attempt exactly one silent token refresh. The HttpOnly refresh cookie is sent
 * automatically by the browser; no Authorization header is attached and this
 * call NEVER triggers another refresh on its own 401. Returns the new access
 * token on success, or `null` when the refresh itself fails.
 */
async function attemptRefresh(): Promise<string | null> {
  let response: Response;
  try {
    response = await rawFetch(REFRESH_PATH, { method: "POST" }, { withAuth: false });
  } catch {
    return null; // Network error — treat as a failed refresh.
  }
  if (!response.ok) {
    return null;
  }
  try {
    const body = (await response.json()) as TokenResponse;
    useAuthStore.getState().setToken(body.access_token);
    return body.access_token;
  } catch {
    return null;
  }
}

/**
 * Perform a JSON request against the versioned API, with silent token refresh.
 *
 * @param path - Path relative to `/api/v1`, starting with `/` (e.g. `/health/ready`).
 * @param init - Standard `fetch` options; JSON headers are applied automatically.
 * @returns The parsed JSON body, typed as `T` (`undefined` for 204 responses).
 * @throws {ApiError} For any non-2xx response (after the single refresh+retry).
 */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  // The refresh endpoint is exempt from the refresh-on-401 dance: refreshing a
  // refresh would recurse, and its 401 simply means the session is dead.
  const isRefreshCall = path === REFRESH_PATH;

  const response = await rawFetch(path, init, { withAuth: true });
  if (response.ok) {
    return parse<T>(response);
  }
  if (response.status !== 401 || isRefreshCall) {
    throw await toApiError(response, path);
  }

  // 401 on a normal request: join the (single-flight) refresh, then retry once.
  const token = await sharedRefresh();
  if (token === null) {
    useAuthStore.getState().setAnon();
    globalThis.location.assign(LOGIN_PATH);
    throw await toApiError(response, path);
  }

  const retried = await rawFetch(path, init, { withAuth: true });
  if (retried.ok) {
    return parse<T>(retried);
  }
  // Do NOT refresh again — a second 401 ends the attempt (no loop).
  throw await toApiError(retried, path);
}
