/**
 * Typed fetch wrapper for the NetOps API mounted at `/api/v1`.
 *
 * Error contract: the backend renders every failure as an RFC 7807
 * problem-details document (`application/problem+json`) — see
 * `backend/app/core/errors.py`. Non-2xx responses become {@link ApiError}
 * instances carrying that document; bodies that are not valid problem
 * documents (e.g. an HTML page from a proxy) are normalized into a synthetic
 * problem so callers always observe one error shape.
 */

/** Versioned API prefix; the dev server proxies it to the FastAPI backend. */
export const API_BASE = "/api/v1";

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
 * Perform a JSON request against the versioned API.
 *
 * @param path - Path relative to `/api/v1`, starting with `/` (e.g. `/health/ready`).
 * @param init - Standard `fetch` options; JSON headers are applied automatically.
 * @returns The parsed JSON body, typed as `T` (`undefined` for 204 responses).
 * @throws {ApiError} For any non-2xx response.
 */
export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json, application/problem+json",
    ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
    ...(init.headers as Record<string, string> | undefined),
  };
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!response.ok) {
    throw await toApiError(response, path);
  }
  if (response.status === 204) {
    return undefined as unknown as T;
  }
  return (await response.json()) as T;
}
