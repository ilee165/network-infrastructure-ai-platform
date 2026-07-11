/**
 * Single-flight refresh guard tests (audit FUNCTIONAL_BUGS #4, Wave 2 item 2).
 *
 * When multiple in-flight requests hit 401 at (roughly) the same moment, the
 * client must coalesce them into EXACTLY ONE `POST /auth/refresh`; every
 * caller awaits the same in-flight promise and retries with the same freshly
 * minted token. A failed refresh rejects all waiters AND clears the in-flight
 * slot so the next 401 can attempt a brand-new refresh (no poisoned cache).
 *
 * This is a prerequisite for refresh-token reuse detection (Wave 2 item 3):
 * without single-flight, two legitimate parallel refreshes would present the
 * same refresh token twice and trip a false reuse alarm.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch } from "../api/client";
import { useAuthStore } from "../stores/auth";

const REFRESH_URL = "/api/v1/auth/refresh";

const PROBLEM_401 = {
  type: "urn:netops:error:auth",
  title: "Unauthorized",
  status: 401,
  detail: "Invalid authentication credentials",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": status >= 400 ? "application/problem+json" : "application/json",
    },
  });
}

function authHeaderOf(init: RequestInit | undefined): string | null {
  const headers = (init?.headers ?? {}) as Record<string, string>;
  return headers.Authorization ?? null;
}

let assignSpy: ReturnType<typeof vi.fn>;

beforeEach(() => {
  useAuthStore.setState({ accessToken: "stale", user: null, status: "authed" });
  assignSpy = vi.fn();
  vi.stubGlobal("location", { assign: assignSpy } as unknown as Location);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiFetch — single-flight refresh (concurrent 401s)", () => {
  it("coalesces two concurrent 401s into exactly one refresh POST and retries both with the new token", async () => {
    let refreshCalls = 0;
    const retriedAuthHeaders: Array<string | null> = [];

    const mock = vi.fn((url: string, init?: RequestInit) => {
      if (url === REFRESH_URL) {
        refreshCalls += 1;
        // Yield to the microtask queue so the second 401 lands while the
        // refresh is still in flight — the exact race the guard must win.
        return new Promise<Response>((resolve) => {
          setTimeout(
            () => resolve(jsonResponse({ access_token: "fresh", token_type: "bearer" })),
            0,
          );
        });
      }
      const auth = authHeaderOf(init);
      if (auth === "Bearer fresh") {
        retriedAuthHeaders.push(auth);
        return Promise.resolve(
          jsonResponse({ path: url.replace("/api/v1", "") }),
        );
      }
      return Promise.resolve(jsonResponse(PROBLEM_401, 401));
    });
    vi.stubGlobal("fetch", mock);

    const [a, b] = await Promise.all([
      apiFetch<{ path: string }>("/devices"),
      apiFetch<{ path: string }>("/users"),
    ]);

    expect(a).toEqual({ path: "/devices" });
    expect(b).toEqual({ path: "/users" });
    expect(refreshCalls).toBe(1);
    // Both originals were retried, each carrying the single new token.
    expect(retriedAuthHeaders).toEqual(["Bearer fresh", "Bearer fresh"]);
    expect(useAuthStore.getState().accessToken).toBe("fresh");
    // 2 originals + 1 refresh + 2 retries = 5 network calls total.
    expect(mock).toHaveBeenCalledTimes(5);
  });

  it("rejects all waiters on a failed shared refresh and lets the NEXT 401 attempt a fresh refresh", async () => {
    let refreshCalls = 0;
    let refreshOutcome: "fail" | "succeed" = "fail";

    const mock = vi.fn((url: string, init?: RequestInit) => {
      if (url === REFRESH_URL) {
        refreshCalls += 1;
        if (refreshOutcome === "fail") {
          return new Promise<Response>((resolve) => {
            setTimeout(() => resolve(jsonResponse(PROBLEM_401, 401)), 0);
          });
        }
        return Promise.resolve(
          jsonResponse({ access_token: "fresh2", token_type: "bearer" }),
        );
      }
      if (authHeaderOf(init) === "Bearer fresh2") {
        return Promise.resolve(jsonResponse({ ok: true }));
      }
      return Promise.resolve(jsonResponse(PROBLEM_401, 401));
    });
    vi.stubGlobal("fetch", mock);

    // Two concurrent callers share ONE failing refresh; both must reject.
    const results = await Promise.allSettled([
      apiFetch("/devices"),
      apiFetch("/users"),
    ]);
    expect(results.map((r) => r.status)).toEqual(["rejected", "rejected"]);
    for (const r of results) {
      expect((r as PromiseRejectedResult).reason).toBeInstanceOf(ApiError);
    }
    expect(refreshCalls).toBe(1);
    expect(useAuthStore.getState().status).toBe("anon");
    expect(assignSpy).toHaveBeenCalledWith("/login");

    // The failed promise must NOT be cached: a later 401 gets a NEW refresh.
    refreshOutcome = "succeed";
    useAuthStore.setState({ accessToken: "stale-again", user: null, status: "authed" });
    const later = await apiFetch<{ ok: boolean }>("/devices");
    expect(later).toEqual({ ok: true });
    expect(refreshCalls).toBe(2);
  });
});

describe("apiFetch — AbortSignal / timeout (M34)", () => {
  it("forwards a combined signal so caller abort cancels the request", async () => {
    const controller = new AbortController();
    let fetchSignal: AbortSignal | undefined;
    const mock = vi.fn((_url: string, init?: RequestInit) => {
      fetchSignal = init?.signal ?? undefined;
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        if (signal?.aborted) {
          reject(new DOMException("Aborted", "AbortError"));
          return;
        }
        signal?.addEventListener("abort", () => {
          reject(new DOMException("Aborted", "AbortError"));
        });
      });
    });
    vi.stubGlobal("fetch", mock);
    useAuthStore.setState({ accessToken: "tok", user: null, status: "authed" });
    const pending = apiFetch("/devices", { signal: controller.signal });
    // Combined signal is not the caller's alone (timeout is fan-in'd).
    expect(fetchSignal).toBeDefined();
    expect(fetchSignal).not.toBe(controller.signal);
    controller.abort();
    await expect(pending).rejects.toThrow();
    expect(mock).toHaveBeenCalled();
  });

  it("timeoutMs null disables the default timeout (caller signal only)", async () => {
    const controller = new AbortController();
    let fetchSignal: AbortSignal | undefined;
    const mock = vi.fn((_url: string, init?: RequestInit) => {
      fetchSignal = init?.signal ?? undefined;
      return Promise.resolve(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );
    });
    vi.stubGlobal("fetch", mock);
    useAuthStore.setState({ accessToken: "tok", user: null, status: "authed" });
    await apiFetch("/devices", { signal: controller.signal, timeoutMs: null });
    expect(fetchSignal).toBe(controller.signal);
  });
});
