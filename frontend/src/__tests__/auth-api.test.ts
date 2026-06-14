/**
 * Unit tests for the typed auth API modules + initAuth boot helper (F1).
 *
 * Verifies each function hits the exact backend path/method from
 * ``backend/app/api/v1/auth.py`` and that the boot sequence is
 * refresh → getMe → authed, or anon on failure, flipping status off "loading".
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  changePassword,
  createUser,
  getMe,
  getSettings,
  getUser,
  initAuth,
  listSessions,
  listUsers,
  login,
  logout,
  refresh,
  resetUserPassword,
  revokeAllSessions,
  revokeSession,
  revokeUserSessions,
  updateMe,
  updateSettings,
  updateUser,
} from "../api/auth";
import { useAuthStore } from "../stores/auth";

const USER_ME = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice",
  role: "admin",
  is_active: true,
  must_change_password: false,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" },
  });
}

function call(mock: ReturnType<typeof vi.fn>, i = 0): { url: string; init: RequestInit } {
  const c = mock.mock.calls[i] as unknown as [string, RequestInit];
  return { url: String(c[0]), init: c[1] ?? {} };
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

describe("auth API — endpoint paths/methods", () => {
  it("login POSTs to /auth/login", async () => {
    const mock = vi.fn(() =>
      Promise.resolve(jsonResponse({ access_token: "t", token_type: "bearer" })),
    );
    vi.stubGlobal("fetch", mock);
    const res = await login("alice", "pw");
    expect(res.access_token).toBe("t");
    const { url, init } = call(mock);
    expect(url).toContain("/api/v1/auth/login");
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ username: "alice", password: "pw" });
  });

  it("refresh POSTs to /auth/refresh", async () => {
    const mock = vi.fn(() =>
      Promise.resolve(jsonResponse({ access_token: "t2", token_type: "bearer" })),
    );
    vi.stubGlobal("fetch", mock);
    await refresh();
    const { url, init } = call(mock);
    expect(url).toContain("/api/v1/auth/refresh");
    expect(init.method).toBe("POST");
  });

  it("logout POSTs to /auth/logout", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ revoked: true })));
    vi.stubGlobal("fetch", mock);
    const res = await logout();
    expect(res.revoked).toBe(true);
    expect(call(mock).url).toContain("/api/v1/auth/logout");
    expect(call(mock).init.method).toBe("POST");
  });

  it("getMe GETs /auth/me", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse(USER_ME)));
    vi.stubGlobal("fetch", mock);
    const me = await getMe();
    expect(me).toEqual(USER_ME);
    expect(call(mock).url).toContain("/api/v1/auth/me");
  });

  it("updateMe PATCHes /auth/me", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse(USER_ME)));
    vi.stubGlobal("fetch", mock);
    await updateMe({ display_name: "Alice Smith" });
    expect(call(mock).url).toContain("/api/v1/auth/me");
    expect(call(mock).init.method).toBe("PATCH");
  });

  it("changePassword POSTs /auth/me/password", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ changed: true })));
    vi.stubGlobal("fetch", mock);
    const res = await changePassword("old", "newpassword");
    expect(res.changed).toBe(true);
    expect(call(mock).url).toContain("/api/v1/auth/me/password");
    expect(JSON.parse(String(call(mock).init.body))).toEqual({
      current_password: "old",
      new_password: "newpassword",
    });
  });

  it("listSessions GETs /auth/sessions", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse([])));
    vi.stubGlobal("fetch", mock);
    await listSessions();
    expect(call(mock).url).toContain("/api/v1/auth/sessions");
  });

  it("revokeSession DELETEs /auth/sessions/{sid}", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ revoked: true })));
    vi.stubGlobal("fetch", mock);
    await revokeSession("sid-1");
    expect(call(mock).url).toContain("/api/v1/auth/sessions/sid-1");
    expect(call(mock).init.method).toBe("DELETE");
  });

  it("revokeAllSessions POSTs /auth/sessions/revoke-all", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ revoked: 2 })));
    vi.stubGlobal("fetch", mock);
    const res = await revokeAllSessions();
    expect(res.revoked).toBe(2);
    expect(call(mock).url).toContain("/api/v1/auth/sessions/revoke-all");
    expect(call(mock).init.method).toBe("POST");
  });
});

describe("auth API — admin endpoints", () => {
  it("listUsers GETs /auth/users", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse([])));
    vi.stubGlobal("fetch", mock);
    await listUsers();
    expect(call(mock).url).toContain("/api/v1/auth/users");
  });

  it("createUser POSTs /auth/users and returns user + temp_password", async () => {
    const mock = vi.fn(() =>
      Promise.resolve(jsonResponse({ user: USER_ME, temp_password: "tmp-xyz" }, 201)),
    );
    vi.stubGlobal("fetch", mock);
    const res = await createUser({ username: "bob", role: "viewer" });
    expect(res.temp_password).toBe("tmp-xyz");
    expect(call(mock).url).toContain("/api/v1/auth/users");
    expect(call(mock).init.method).toBe("POST");
  });

  it("getUser GETs /auth/users/{id}", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse(USER_ME)));
    vi.stubGlobal("fetch", mock);
    await getUser("uid-1");
    expect(call(mock).url).toContain("/api/v1/auth/users/uid-1");
  });

  it("updateUser PATCHes /auth/users/{id}", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse(USER_ME)));
    vi.stubGlobal("fetch", mock);
    await updateUser("uid-1", { role: "operator" });
    expect(call(mock).url).toContain("/api/v1/auth/users/uid-1");
    expect(call(mock).init.method).toBe("PATCH");
  });

  it("resetUserPassword POSTs /auth/users/{id}/reset-password", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ temp_password: "tmp-2" })));
    vi.stubGlobal("fetch", mock);
    const res = await resetUserPassword("uid-1");
    expect(res.temp_password).toBe("tmp-2");
    expect(call(mock).url).toContain("/api/v1/auth/users/uid-1/reset-password");
    expect(call(mock).init.method).toBe("POST");
  });

  it("resetUserPassword forwards an explicit temp_password", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ temp_password: "chosen" })));
    vi.stubGlobal("fetch", mock);
    await resetUserPassword("uid-1", "chosen");
    expect(JSON.parse(String(call(mock).init.body))).toEqual({ temp_password: "chosen" });
  });

  it("revokeUserSessions POSTs /auth/users/{id}/revoke-sessions", async () => {
    const mock = vi.fn(() => Promise.resolve(jsonResponse({ revoked: 3 })));
    vi.stubGlobal("fetch", mock);
    const res = await revokeUserSessions("uid-1");
    expect(res.revoked).toBe(3);
    expect(call(mock).url).toContain("/api/v1/auth/users/uid-1/revoke-sessions");
    expect(call(mock).init.method).toBe("POST");
  });

  it("getSettings GETs /auth/settings", async () => {
    const mock = vi.fn(() =>
      Promise.resolve(
        jsonResponse({ llm_profile: "p", llm_role_reasoning: null, llm_role_fast: null }),
      ),
    );
    vi.stubGlobal("fetch", mock);
    const res = await getSettings();
    expect(res.llm_profile).toBe("p");
    expect(call(mock).url).toContain("/api/v1/auth/settings");
  });

  it("updateSettings PATCHes /auth/settings", async () => {
    const mock = vi.fn(() =>
      Promise.resolve(
        jsonResponse({ llm_profile: "p2", llm_role_reasoning: null, llm_role_fast: null }),
      ),
    );
    vi.stubGlobal("fetch", mock);
    await updateSettings({ llm_profile: "p2" });
    expect(call(mock).url).toContain("/api/v1/auth/settings");
    expect(call(mock).init.method).toBe("PATCH");
  });
});

describe("initAuth — boot sequence", () => {
  it("refresh → getMe → authed on success, status off loading", async () => {
    const mock = vi
      .fn()
      // refresh ok
      .mockResolvedValueOnce(jsonResponse({ access_token: "boot-tok", token_type: "bearer" }))
      // getMe ok
      .mockResolvedValueOnce(jsonResponse(USER_ME));
    vi.stubGlobal("fetch", mock);

    await initAuth();

    const state = useAuthStore.getState();
    expect(state.status).toBe("authed");
    expect(state.accessToken).toBe("boot-tok");
    expect(state.user).toEqual(USER_ME);
    // getMe (call 2) must carry the freshly minted bearer token
    const second = mock.mock.calls[1] as unknown as [string, RequestInit];
    const headers = (second[1].headers ?? {}) as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer boot-tok");
  });

  it("sets anon when refresh fails (no cookie / 401)", async () => {
    const mock = vi.fn(() =>
      Promise.resolve(
        jsonResponse(
          { type: "x", title: "Unauthorized", status: 401, detail: "no cookie" },
          401,
        ),
      ),
    );
    vi.stubGlobal("fetch", mock);

    await initAuth();

    const state = useAuthStore.getState();
    expect(state.status).toBe("anon");
    expect(state.accessToken).toBeNull();
    expect(state.user).toBeNull();
  });

  it("does not redirect to /login when the boot refresh 401s", async () => {
    const mock = vi.fn(() =>
      Promise.resolve(
        jsonResponse(
          { type: "x", title: "Unauthorized", status: 401, detail: "no cookie" },
          401,
        ),
      ),
    );
    vi.stubGlobal("fetch", mock);

    await initAuth();

    expect(assignSpy).not.toHaveBeenCalled();
  });
});
