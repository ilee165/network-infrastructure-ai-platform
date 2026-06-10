# ADR-0010: Authentication and Authorization

**Status:** Accepted | **Date:** 2026-06-09 | **Decision:** D10

## Context

CLAUDE.md requires **"Secure by default"**, **"Enterprise ready"**, and **"Audit everything"**; every action in the audit log must be attributable to a human or agent actor. The brief's security architecture (section 7) adds a hard constraint: *agents inherit the invoking user's permissions — an agent can never do what its user cannot*, and ChangeRequest approvals require a different user than the requester. The brief (D10) fixes: local users + OIDC (pluggable), short-lived JWT access tokens, and four RBAC roles: `viewer`, `operator`, `engineer`, `admin`. The MVP milestones put an auth skeleton in M0 and defer OIDC to the production roadmap (brief section 8).

## Decision

1. **Two pluggable identity sources behind one `IdentityProvider` interface** in `backend/app/core/security`:
   - **Local users** (MVP, M0): username/password stored in the Postgres `users` table. **PROPOSED:** password hashing with Argon2id via `argon2-cffi` (the brief mandates local users but not a hash algorithm; Argon2id is the conservative OWASP-recommended choice).
   - **OIDC** (production roadmap): Authorization Code flow with PKCE against an enterprise IdP (Entra ID, Okta, Keycloak). **PROPOSED:** implemented with `Authlib` (the brief says "pluggable" without naming a library). IdP group claims map to platform roles via a configurable `group → role` table.

2. **Tokens.** Login issues a **short-lived JWT access token** and a rotating refresh token:
   - Access token lifetime **PROPOSED: 15 minutes**; refresh token **PROPOSED: 8 hours, rotated on use, revocable server-side** (lifetimes are not specified in the brief).
   - **PROPOSED:** JWTs signed with an asymmetric key (RS256) generated at install, via `PyJWT`; claims: `sub`, `roles`, `session_id`, `exp`, `iat`, `iss`.
   - The refresh token is delivered as an `HttpOnly; Secure; SameSite=Strict` cookie; the access token is held in memory by the React app (never `localStorage`).
   - WebSocket connections (chat/agent streaming, D3/D12) authenticate with the same access token at upgrade time and are closed when the token expires without refresh.

3. **RBAC — four roles, enforced at the API layer** via FastAPI dependencies (`require_role(...)` / permission-checking dependencies on every router in `backend/app/api/v1/`):

   | Role | Permissions |
   |---|---|
   | `viewer` | Read everything non-secret: inventory, topology, audit log, reasoning traces, documents. No agent execution. |
   | `operator` | `viewer` + run read-only agent sessions, trigger discovery runs, request packet captures, run config backups. |
   | `engineer` | `operator` + create/edit ChangeRequests (config deploy, DDI changes, automation), approve ChangeRequests (requester ≠ approver per D11), manage compliance policies, download pcaps. |
   | `admin` | `engineer` + manage users/roles, manage device credentials (write-only), platform settings, LLM profiles. |

   **PROPOSED:** approval rights sit at `engineer`+ (matching the consultant working default A4/Q4 and the DIAGRAMS.md system-context diagram), with a setting to restrict approval to `admin` only for stricter shops (the four-eyes rule from D11 — approver ≠ requester — still applies regardless). The brief defines the role names but not the exact permission matrix; the matrix above is the binding starting point.

4. **Agents impersonate nothing.** Every agent session row (`agent_sessions`) stores the invoking user id; the agent framework's tool wrappers (brief section 5) re-check that user's permissions on **every tool call**, not just at session start. A state-changing tool invoked by an agent on behalf of a `viewer` fails authorization exactly as a direct API call would.

5. **Credentials API is asymmetric.** Per D11, device credentials are write-only at the API: even `admin` can create/rotate but never read back secrets.

6. **Bootstrap.** First-run creates a single `admin` account with a forced password change on first login; no default password ships in images (secure by default).

## Consequences

**Positive**
- Works fully offline with local users (local-first), and slots into enterprise SSO later without touching route-level enforcement (enterprise-ready).
- Short-lived stateless access tokens keep API and WebSocket auth cheap and horizontally scalable; revocation risk is bounded to ≤15 minutes plus server-side refresh revocation.
- The agent-inherits-user rule plus per-tool-call checks closes the "confused deputy" hole — the most dangerous failure mode for an AI platform that can touch routers and firewalls.
- Four coarse roles are simple to reason about, audit, and explain to enterprise security reviewers.

**Negative**
- JWTs cannot be instantly revoked; a compromised access token is valid until expiry. Mitigated by the short lifetime and revocable refresh tokens, but it is a real tradeoff vs. server-side sessions.
- Coarse RBAC has no per-device/per-site scoping (e.g. "engineer for site A only"); multi-tenancy and scoped permissions are open items already routed to the Consultant Agent (brief section 9).
- Two identity paths (local + OIDC) double the auth test surface and the security-review surface.
- Role→permission matrix changes require a release (it is code/config, not a runtime policy engine).

## Alternatives considered

1. **Server-side sessions (cookie + Redis session store) instead of JWT.** Honest tradeoff — instant revocation and smaller token surface — but rejected because the brief explicitly fixes short-lived JWTs (D10), JWTs carry role claims into WebSocket handlers and Celery-dispatched agent work without a session-store round trip, and stateless verification simplifies the K8s multi-replica `api` deployment (D13).
2. **Bundling a dedicated IdP (Keycloak) as a platform container and using it for *all* auth, including local users.** Rejected: adds a heavyweight JVM service to the self-hosted footprint, makes the MVP depend on configuring an IdP before first login, and conflicts with "local first" simplicity. OIDC support (which can point at a customer-operated Keycloak) achieves the same end state.
3. **API keys / static tokens per user.** Rejected: no expiry, weak attribution for the audit log, no role claims, and unacceptable for an interactive approval workflow. Long-lived service tokens may be introduced later for machine integrations, but as an addition, not the foundation.
4. **Full ABAC / policy engine (OPA, Casbin, Cedar) from day one.** Rejected for MVP: a policy engine adds a new language and runtime to secure and audit, while the four-role matrix covers every M0–M5 use case. The FastAPI-dependency enforcement point keeps the door open to swap a policy engine in behind the same checks.
