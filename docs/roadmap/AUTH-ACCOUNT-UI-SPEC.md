# Milestone Spec — Auth & Account UI

**Status:** Approved design, ready to plan + build. Inserted milestone (between M3 and MVP M4).
**Driver:** M3 live test — the SPA boots straight to the dashboard; the frontend has **no auth code at all** (no login, route gate, or token handling) and no account/settings/profile area. Backend auth is `login` + `refresh` (HttpOnly cookie) only.
**Stack:** React+TS+Vite, TanStack Query, Zustand, Tailwind; FastAPI, async SQLAlchemy, JWT, RBAC `viewer<operator<engineer<admin`, append-only `audit_log`.

## Scope
Login gate + logout + silent refresh; admin user management; profile; settings (theme + admin LLM profile select); server-side session tracking; forced first-login password change.

## Locked decisions
- **Token model:** in-memory access JWT + the existing HttpOnly/Secure/SameSite=strict refresh cookie; silent refresh on boot; api client retries once on 401, else redirects to login. (No access token in localStorage.)
- **Sessions are server-side:** `refresh_sessions` table; refresh JWT carries a `sid` claim; refresh validates the session is live + user active; revoke flips `revoked_at`. Effective within one 30-min access-token life.
- **LLM profile select is DB-persisted:** a single `system_settings` row the LLM registry reads at runtime (env fallback). Provider API keys stay in env — never entered/stored via the UI.
- **Users are admin-only created** with a temp password + forced change on first login. No SMTP, no self-signup.
- **Settings ride the `auth` router** — brief §3 fixes the 10 v1 routers, so no new router is added.

## Data model (migration `0005`)
- `users` add: `email` (nullable, unique), `display_name` (nullable), `must_change_password` (bool, default false). (`is_active` already exists; single `role_id` FK.)
- `refresh_sessions` (new): `id, user_id FK, created_at, last_used_at, user_agent, ip, revoked_at?`.
- `system_settings` (new, single admin row): `llm_profile, llm_role_reasoning, llm_role_fast`.

## Backend API (all under `/api/v1/auth`)
- `GET /me` · `PATCH /me` (email, display_name) · `POST /me/password` (change own; clears `must_change_password`)
- `POST /logout` (revoke current session + clear cookie)
- `GET /sessions` · `DELETE /sessions/{sid}` · `POST /sessions/revoke-all` (own)
- **[admin]** `GET/POST /users` · `GET/PATCH /users/{id}` (role, is_active, email, display_name) · `POST /users/{id}/reset-password` · `POST /users/{id}/revoke-sessions`
- **[admin]** `GET/PATCH /settings` (llm profile + role map)
- `refresh` validates session live + user active; access JWT 30 min, refresh 8 h.

## Frontend
- **Auth store (Zustand):** in-memory access token, `user`, `status: loading|authed|anon`. Boot: `refresh` → `/me` → authed/anon.
- **api/client.ts:** inject Bearer; on 401 → one `/refresh` retry → else anon → redirect `/login`.
- **Routing:** public `/login`; `ProtectedRoute` gates the app; `must_change_password` forces `/change-password` before anything; `RoleRoute(admin)` for Users + LLM settings.
- **Pages:** `LoginPage`; `ChangePasswordPage` (also forced); `ProfilePage` (info + edit email/display_name, change password, sessions list/revoke, own recent audit); `SettingsPage` (Appearance: theme; LLM[admin]: profile + role map); `UsersPage` (admin: table, create-with-temp-password, edit role, activate/deactivate, reset password, revoke sessions). **Layout:** user menu (name + role), logout, nav links.
- **Theme:** store + Tailwind `darkMode:'class'`; light/dark/system; persisted to localStorage.

## RBAC
Public: login. Any authenticated: profile, own sessions, change password, theme, own audit. Admin only: user management, LLM settings, revoke others' sessions/passwords. Backend `require_role` is the source of truth; frontend guards are defense-in-depth.

## Guards & audit
- Forced change blocks the app + sensitive endpoints until cleared.
- Deactivate (`is_active=false`) → login refused + sessions revoked.
- Last-admin guard: cannot deactivate/demote the final admin (lockout prevention).
- Audit: login ok/fail, logout, password change, user CRUD, role change, session revoke, settings change.

## Testing / exit criteria
- **Backend:** login/refresh/logout/forced-change; session create/revoke/all; user CRUD + RBAC denials; settings admin-only; deactivate-refuses-login; last-admin guard; no secret/hash leak.
- **Frontend:** login form, gate redirect, forced-change gate, role routes, profile edit + password change, sessions revoke, admin user table, theme persist.
- **Exit:** unauth→login; bad creds rejected+audited; gate blocks until auth; admin-creates-user→login→forced-change; viewer blocked from admin (UI **and** API); logout invalidates the old refresh; theme persists; all gates green (pytest, ruff, mypy, import-linter, vitest, eslint, tsc).

## Build notes (next session)
- Cut a feature branch (e.g. `feature/auth-account-ui`).
- Orchestrated workflow + `.claude/agents` tiering; review-trigger rule = dual + strong reviewers on security/high-uncertainty — auth is security-heavy, so most tasks are dual + strong.
- Verify the `users`/`auth.py`/llm-registry assumptions in code before each task.
