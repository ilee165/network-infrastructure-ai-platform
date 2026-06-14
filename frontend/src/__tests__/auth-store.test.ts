/**
 * Unit tests for the in-memory auth store (Auth & Account UI, F1).
 *
 * The access token is held in memory ONLY (never localStorage/sessionStorage)
 * and must be readable OUTSIDE React via ``useAuthStore.getState()`` so the
 * non-React api client can attach it as a Bearer header.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

const USER: UserMe = {
  id: "11111111-1111-1111-1111-111111111111",
  username: "alice",
  email: "alice@example.com",
  display_name: "Alice",
  role: "admin",
  is_active: true,
  must_change_password: false,
};

function resetStore(): void {
  useAuthStore.setState({ accessToken: null, user: null, status: "loading" });
}

beforeEach(resetStore);
afterEach(resetStore);

describe("auth store — initial state", () => {
  it("starts in the loading status with no token or user", () => {
    const state = useAuthStore.getState();
    expect(state.status).toBe("loading");
    expect(state.accessToken).toBeNull();
    expect(state.user).toBeNull();
  });
});

describe("auth store — setAuth", () => {
  it("stores the token + user and flips status to authed", () => {
    useAuthStore.getState().setAuth("tok-123", USER);
    const state = useAuthStore.getState();
    expect(state.accessToken).toBe("tok-123");
    expect(state.user).toEqual(USER);
    expect(state.status).toBe("authed");
  });
});

describe("auth store — token is readable outside React", () => {
  it("exposes the current token via getState() for the api client", () => {
    useAuthStore.getState().setAuth("bearer-xyz", USER);
    expect(useAuthStore.getState().accessToken).toBe("bearer-xyz");
  });

  it("never persists the token to localStorage or sessionStorage", () => {
    useAuthStore.getState().setAuth("secret-token", USER);
    expect(globalThis.localStorage.getItem("netops.access_token")).toBeNull();
    const localDump = JSON.stringify(globalThis.localStorage);
    const sessionDump = JSON.stringify(globalThis.sessionStorage);
    expect(localDump).not.toContain("secret-token");
    expect(sessionDump).not.toContain("secret-token");
  });
});

describe("auth store — setToken", () => {
  it("replaces only the token, leaving user + status intact", () => {
    useAuthStore.getState().setAuth("old", USER);
    useAuthStore.getState().setToken("rotated");
    const state = useAuthStore.getState();
    expect(state.accessToken).toBe("rotated");
    expect(state.user).toEqual(USER);
    expect(state.status).toBe("authed");
  });
});

describe("auth store — setUser", () => {
  it("replaces only the user, leaving the token intact", () => {
    useAuthStore.getState().setAuth("tok", USER);
    const updated: UserMe = { ...USER, display_name: "Alice Smith" };
    useAuthStore.getState().setUser(updated);
    const state = useAuthStore.getState();
    expect(state.user).toEqual(updated);
    expect(state.accessToken).toBe("tok");
  });
});

describe("auth store — setAnon", () => {
  it("clears the token + user and flips status to anon", () => {
    useAuthStore.getState().setAuth("tok", USER);
    useAuthStore.getState().setAnon();
    const state = useAuthStore.getState();
    expect(state.accessToken).toBeNull();
    expect(state.user).toBeNull();
    expect(state.status).toBe("anon");
  });
});
