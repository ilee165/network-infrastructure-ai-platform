/**
 * Auth store (Auth & Account UI, F1): the in-memory access token + current user.
 *
 * SECURITY — the access JWT lives in memory ONLY. It is never written to
 * ``localStorage``/``sessionStorage`` (those survive a tab and are reachable by
 * any same-origin script — an XSS token-theft surface). The long-lived refresh
 * token is the browser's ``HttpOnly`` cookie, which JS cannot read; the access
 * token is re-minted from it on boot and on a 401 (see ``api/client.ts``).
 *
 * The token must be readable OUTSIDE React (the non-React api client attaches it
 * as a Bearer header), which Zustand supports via ``useAuthStore.getState()``.
 */

import { create } from "zustand";

/**
 * The authenticated user's own profile, matching the backend ``GET /auth/me``
 * (``UserMe`` in ``backend/app/api/v1/auth.py``). Carries no credential
 * material — ``role`` is the flattened role *name* (the wire value).
 */
export interface UserMe {
  id: string;
  username: string;
  email: string | null;
  display_name: string | null;
  role: string;
  is_active: boolean;
  must_change_password: boolean;
}

/** Boot/auth lifecycle: ``loading`` until the boot refresh resolves. */
export type AuthStatus = "loading" | "authed" | "anon";

export interface AuthState {
  /** In-memory access JWT, or ``null`` when unauthenticated. Never persisted. */
  accessToken: string | null;
  /** The current user's profile, or ``null`` when unauthenticated. */
  user: UserMe | null;
  /** Where the session is in its lifecycle. */
  status: AuthStatus;
  /** Set token + user and mark the session authenticated (login / boot success). */
  setAuth: (token: string, user: UserMe) => void;
  /** Rotate just the access token (e.g. after a silent refresh). */
  setToken: (token: string) => void;
  /** Replace just the cached user (e.g. after a profile edit). */
  setUser: (user: UserMe) => void;
  /** Clear all auth state and mark the session anonymous. */
  setAnon: () => void;
}

export const useAuthStore = create<AuthState>()((set) => ({
  accessToken: null,
  user: null,
  status: "loading",
  setAuth: (accessToken, user) => set({ accessToken, user, status: "authed" }),
  setToken: (accessToken) => set({ accessToken }),
  setUser: (user) => set({ user }),
  setAnon: () => set({ accessToken: null, user: null, status: "anon" }),
}));
