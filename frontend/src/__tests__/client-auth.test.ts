/**
 * Unit tests for the token-aware api client (Auth & Account UI, F1).
 *
 * apiFetch must (a) inject ``Authorization: Bearer <token>`` from the in-memory
 * auth store, (b) on a 401 perform EXACTLY ONE ``POST /api/v1/auth/refresh``
 * (cookie-carried, no Authorization header) then retry the original request
 * once, and (c) on refresh failure set the store anon and redirect to /login.
 * The refresh call itself is never retried/refreshed; never loop.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch } from "../api/client";
import { useAuthStore } from "../stores/auth";

const PROBLEM_401 = {
  type: "urn:netops:error:auth",
  title: "Unauthorized",
  status: 401,
  detail: "Invalid authentication credentials",
  instance: "/api/v1/devices",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" },
  });
}

function headerOf(call: unknown, name: string): string | null {
  const init = (call as [string, RequestInit])[1];
  const headers = (init.headers ?? {}) as Record<string, string>;
  return headers[name] ?? null;
}

function pathOf(call: unknown): string {
  return String((call as [string])[0]);
}

let assignSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  useAuthStore.setState({ accessToken: null, user: null, status: "loading" });
  assignSpy = vi.fn();
  vi.stubGlobal("location", { assign: assignSpy } as unknown as Location);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiFetch — Bearer injection", () => {
  it("attaches Authorization: Bearer from the auth store when a token is present", async () => {
    useAuthStore.setState({ accessToken: "tok-abc", status: "authed" });
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ ok: true })));
    vi.stubGlobal("fetch", mock);

    await apiFetch("/devices");

    expect(headerOf(mock.mock.calls[0], "Authorization")).toBe("Bearer tok-abc");
  });

  it("omits the Authorization header when no token is present", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ ok: true })));
    vi.stubGlobal("fetch", mock);

    await apiFetch("/health/ready");

    expect(headerOf(mock.mock.calls[0], "Authorization")).toBeNull();
  });
});

describe("apiFetch — 401 refresh + retry (happy path)", () => {
  it("refreshes once and retries the original request with the new token", async () => {
    useAuthStore.setState({ accessToken: "stale", status: "authed" });
    const mock = vi
      .fn()
      // 1: original request → 401
      .mockResolvedValueOnce(jsonResponse(PROBLEM_401, 401))
      // 2: refresh → new token
      .mockResolvedValueOnce(jsonResponse({ access_token: "fresh", token_type: "bearer" }))
      // 3: retried original → 200
      .mockResolvedValueOnce(jsonResponse({ value: 42 }));
    vi.stubGlobal("fetch", mock);

    const result = await apiFetch<{ value: number }>("/devices");

    expect(result).toEqual({ value: 42 });
    expect(mock).toHaveBeenCalledTimes(3);
    // call 2 is the refresh — cookie-carried, NO Authorization header
    expect(pathOf(mock.mock.calls[1])).toContain("/api/v1/auth/refresh");
    expect(headerOf(mock.mock.calls[1], "Authorization")).toBeNull();
    // call 3 is the retry — carries the freshly minted token
    expect(headerOf(mock.mock.calls[2], "Authorization")).toBe("Bearer fresh");
    // store token was rotated
    expect(useAuthStore.getState().accessToken).toBe("fresh");
  });
});

describe("apiFetch — refresh failure sets anon + redirects", () => {
  it("sets the store anon and redirects to /login when refresh also 401s", async () => {
    useAuthStore.setState({ accessToken: "stale", user: null, status: "authed" });
    const mock = vi
      .fn()
      // 1: original request → 401
      .mockResolvedValueOnce(jsonResponse(PROBLEM_401, 401))
      // 2: refresh → 401
      .mockResolvedValueOnce(jsonResponse(PROBLEM_401, 401));
    vi.stubGlobal("fetch", mock);

    await expect(apiFetch("/devices")).rejects.toBeInstanceOf(ApiError);

    expect(mock).toHaveBeenCalledTimes(2); // original + one refresh, NO further retry
    expect(useAuthStore.getState().status).toBe("anon");
    expect(useAuthStore.getState().accessToken).toBeNull();
    expect(assignSpy).toHaveBeenCalledWith("/login");
  });
});

describe("apiFetch — never refresh the refresh call itself", () => {
  it("does not attempt a nested refresh when /auth/refresh returns 401", async () => {
    const mock = vi.fn().mockResolvedValue(jsonResponse(PROBLEM_401, 401));
    vi.stubGlobal("fetch", mock);

    await expect(
      apiFetch("/auth/refresh", { method: "POST" }),
    ).rejects.toBeInstanceOf(ApiError);

    // Exactly one network call: the refresh request itself, never recursed.
    expect(mock).toHaveBeenCalledTimes(1);
  });
});

describe("apiFetch — single retry only (no loops)", () => {
  it("does not refresh more than once if the retried request also 401s", async () => {
    useAuthStore.setState({ accessToken: "stale", status: "authed" });
    const mock = vi
      .fn()
      // 1: original → 401
      .mockResolvedValueOnce(jsonResponse(PROBLEM_401, 401))
      // 2: refresh → ok
      .mockResolvedValueOnce(jsonResponse({ access_token: "fresh", token_type: "bearer" }))
      // 3: retried original → 401 again
      .mockResolvedValueOnce(jsonResponse(PROBLEM_401, 401));
    vi.stubGlobal("fetch", mock);

    await expect(apiFetch("/devices")).rejects.toBeInstanceOf(ApiError);

    // original + refresh + one retry = 3; the second 401 is NOT refreshed again.
    expect(mock).toHaveBeenCalledTimes(3);
  });
});

describe("apiFetch — non-401 errors are untouched", () => {
  it("does not attempt a refresh on a 404", async () => {
    useAuthStore.setState({ accessToken: "tok", status: "authed" });
    const problem404 = { ...PROBLEM_401, status: 404, title: "Not Found" };
    const mock = vi.fn(() => Promise.resolve(jsonResponse(problem404, 404)));
    vi.stubGlobal("fetch", mock);

    await expect(apiFetch("/devices/x")).rejects.toBeInstanceOf(ApiError);
    expect(mock).toHaveBeenCalledTimes(1);
  });
});
