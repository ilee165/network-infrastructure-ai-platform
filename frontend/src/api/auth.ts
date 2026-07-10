/**
 * Typed client functions for the auth + account endpoints (Auth & Account UI).
 *
 * Mirrors the routes + schemas in ``backend/app/api/v1/auth.py`` exactly — all
 * paths are under ``/api/v1/auth``. Provider API keys are NEVER part of any
 * request/response here: the settings endpoints only carry the LLM profile
 * selection + role map (the backend has no body field for secrets).
 */

import { apiFetch, REFRESH_PATH } from "./client";
import type { UserMe } from "../stores/auth";
import { useAuthStore } from "../stores/auth";

// ── Token + session lifecycle ─────────────────────────────────────────────────

/** ``{ access_token, token_type }`` returned by login + refresh. */
export interface TokenResponse {
  access_token: string;
  token_type: string;
}

/** One row of the caller's "your sessions" view (``GET /auth/sessions``). */
export interface SessionInfo {
  sid: string;
  created_at: string;
  last_used_at: string;
  user_agent: string | null;
  ip: string | null;
  revoked_at: string | null;
  is_current: boolean;
}

/** ``POST /auth/login`` — exchange credentials for an access token + refresh cookie. */
export function login(username: string, password: string): Promise<TokenResponse> {
  return apiFetch<TokenResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

/** ``POST /auth/refresh`` — rotate the access token using the HttpOnly cookie. */
export function refresh(): Promise<TokenResponse> {
  return apiFetch<TokenResponse>(REFRESH_PATH, { method: "POST" });
}

/** ``POST /auth/logout`` — revoke the current session + clear the refresh cookie. */
export function logout(): Promise<{ revoked: boolean }> {
  return apiFetch<{ revoked: boolean }>("/auth/logout", { method: "POST" });
}

// ── Self-service profile ──────────────────────────────────────────────────────

/** Editable own-profile fields for ``PATCH /auth/me`` (both optional). */
export interface UpdateMePayload {
  email?: string | null;
  display_name?: string | null;
}

/** ``GET /auth/me`` — the authenticated user's own profile. */
export function getMe(): Promise<UserMe> {
  return apiFetch<UserMe>("/auth/me");
}

/** ``PATCH /auth/me`` — update the caller's own email / display name. */
export function updateMe(patch: UpdateMePayload): Promise<UserMe> {
  return apiFetch<UserMe>("/auth/me", {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

/** ``POST /auth/me/password`` — change own password (clears must_change_password). */
export function changePassword(
  current_password: string,
  new_password: string,
): Promise<{ changed: boolean }> {
  return apiFetch<{ changed: boolean }>("/auth/me/password", {
    method: "POST",
    body: JSON.stringify({ current_password, new_password }),
  });
}

/** ``GET /auth/sessions`` — the caller's own sessions. */
export function listSessions(): Promise<SessionInfo[]> {
  return apiFetch<SessionInfo[]>("/auth/sessions");
}

/** ``DELETE /auth/sessions/{sid}`` — revoke one of the caller's own sessions. */
export function revokeSession(sid: string): Promise<{ revoked: boolean }> {
  return apiFetch<{ revoked: boolean }>(`/auth/sessions/${sid}`, { method: "DELETE" });
}

/** ``POST /auth/sessions/revoke-all`` — revoke every live session of the caller. */
export function revokeAllSessions(): Promise<{ revoked: number }> {
  return apiFetch<{ revoked: number }>("/auth/sessions/revoke-all", { method: "POST" });
}

// ── Admin: user management ────────────────────────────────────────────────────

/** Admin-visible account projection (``UserSummary``); same shape as ``UserMe``. */
export type UserSummary = UserMe;

/** Body for ``POST /auth/users`` — admin creates an account with a temp password. */
export interface CreateUserPayload {
  username: string;
  role: string;
  email?: string | null;
  display_name?: string | null;
  temp_password?: string | null;
}

/** ``POST /auth/users`` result: the created account + the one-time temp password. */
export interface CreatedUserResponse {
  user: UserSummary;
  temp_password: string;
}

/** Body for ``PATCH /auth/users/{id}`` — every field optional (partial update). */
export interface UpdateUserPayload {
  role?: string;
  is_active?: boolean;
  email?: string | null;
  display_name?: string | null;
}

/** ``GET /auth/users`` — list every account (admin only). */
export function listUsers(): Promise<UserSummary[]> {
  return apiFetch<UserSummary[]>("/auth/users");
}

/** ``POST /auth/users`` — create an account; returns the one-time temp password. */
export function createUser(payload: CreateUserPayload): Promise<CreatedUserResponse> {
  return apiFetch<CreatedUserResponse>("/auth/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/** ``GET /auth/users/{id}`` — one account by id (admin only). */
export function getUser(id: string): Promise<UserSummary> {
  return apiFetch<UserSummary>(`/auth/users/${id}`);
}

/** ``PATCH /auth/users/{id}`` — update role / active flag / email / display name. */
export function updateUser(id: string, patch: UpdateUserPayload): Promise<UserSummary> {
  return apiFetch<UserSummary>(`/auth/users/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

/**
 * ``POST /auth/users/{id}/reset-password`` — set a forced-change temp password.
 *
 * When *temp_password* is omitted the backend generates a strong random one; the
 * plaintext is returned exactly once.
 */
export function resetUserPassword(
  id: string,
  temp_password?: string,
): Promise<{ temp_password: string }> {
  const body = temp_password !== undefined ? { temp_password } : {};
  return apiFetch<{ temp_password: string }>(`/auth/users/${id}/reset-password`, {
    method: "POST",
    body: JSON.stringify(body),
  });
}

/** ``POST /auth/users/{id}/revoke-sessions`` — revoke every live session of an account. */
export function revokeUserSessions(id: string): Promise<{ revoked: number }> {
  return apiFetch<{ revoked: number }>(`/auth/users/${id}/revoke-sessions`, { method: "POST" });
}

// ── Admin: system (LLM) settings ──────────────────────────────────────────────

/** The effective LLM profile selection (``GET/PATCH /auth/settings``). */
export interface SystemSettings {
  llm_profile: string;
  llm_role_reasoning: string | null;
  llm_role_fast: string | null;
}

/** Body for ``PATCH /auth/settings`` — every field optional; no secret fields. */
export interface UpdateSettingsPayload {
  llm_profile?: string;
  llm_role_reasoning?: string | null;
  llm_role_fast?: string | null;
}

/** ``GET /auth/settings`` — the effective LLM profile selection (admin only). */
export function getSettings(): Promise<SystemSettings> {
  return apiFetch<SystemSettings>("/auth/settings");
}

/** ``PATCH /auth/settings`` — upsert the LLM profile + role map (admin only). */
export function updateSettings(patch: UpdateSettingsPayload): Promise<SystemSettings> {
  return apiFetch<SystemSettings>("/auth/settings", {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
}

/**
 * Non-secret active profile for the shell badge (any authenticated user).
 * ``GET /auth/llm-profile`` — never returns keys or endpoints.
 */
export interface LlmProfileStatus {
  llm_profile: string;
}

/** ``GET /auth/llm-profile`` — runtime profile name for UI badges. */
export function getLlmProfile(): Promise<LlmProfileStatus> {
  return apiFetch<LlmProfileStatus>("/auth/llm-profile");
}

// ── Admin: LLM readiness + connection test ───────────────────────────────────

/** Per-profile readiness row (``GET /auth/settings/llm-readiness``). */
export type LlmProfileProbeStatus = "ready" | "not_configured" | "unreachable" | "error";

export interface LlmProfileReadiness {
  profile: string;
  configured: boolean;
  status: LlmProfileProbeStatus;
  model: string;
  egress: boolean;
  models: string[];
  detail: string | null;
  latency_ms: number | null;
}

export interface LlmReadinessReport {
  active_profile: string;
  local_model: string;
  profiles: LlmProfileReadiness[];
}

/** Result of ``POST /auth/settings/llm-test``. */
export type LlmProbeResult = LlmProfileReadiness;

/** ``GET /auth/settings/llm-readiness`` — static configured? status (admin). */
export function getLlmReadiness(): Promise<LlmReadinessReport> {
  return apiFetch<LlmReadinessReport>("/auth/settings/llm-readiness");
}

/** ``POST /auth/settings/llm-test`` — live connection probe (admin). */
export function testLlmConnection(profile: string): Promise<LlmProbeResult> {
  return apiFetch<LlmProbeResult>("/auth/settings/llm-test", {
    method: "POST",
    body: JSON.stringify({ profile }),
  });
}

// ── Admin: OIDC status (non-secret) ───────────────────────────────────────────

/** Non-secret OIDC flags from ``GET /auth/settings/oidc-status``. */
export interface OidcStatus {
  enabled: boolean;
  issuer_configured: boolean;
  client_id_configured: boolean;
  /** True when a vault secret-ref is configured; the ref string is never returned. */
  client_ref_configured: boolean;
  redirect_uri: string;
  break_glass_local_admin_only: boolean;
  allow_admin_via_oidc: boolean;
}

/** ``GET /auth/settings/oidc-status`` — SSO enablement for Settings access (admin). */
export function getOidcStatus(): Promise<OidcStatus> {
  return apiFetch<OidcStatus>("/auth/settings/oidc-status");
}

// ── Boot helper ───────────────────────────────────────────────────────────────

/**
 * Boot the auth session: ``refresh`` → ``getMe`` → mark authed; on any failure
 * mark anonymous. Either way the store leaves the ``loading`` status so the app
 * shell can render the login gate or the protected tree.
 *
 * A boot-time refresh failure is expected (no/expired cookie) and must NOT
 * redirect — that's the job of the in-flight 401 handler, not the cold boot.
 * ``refresh`` targets the refresh path, which ``apiFetch`` exempts from the
 * 401 refresh/redirect dance, so a failed boot here simply rejects.
 */
export async function initAuth(): Promise<void> {
  const store = useAuthStore.getState();
  try {
    const { access_token } = await refresh();
    store.setToken(access_token);
    const user = await getMe();
    store.setAuth(access_token, user);
  } catch {
    store.setAnon();
  }
}
