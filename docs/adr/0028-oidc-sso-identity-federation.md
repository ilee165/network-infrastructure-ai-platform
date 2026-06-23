# ADR-0028: OIDC / SSO Identity Federation

**Status:** Accepted | **Date:** 2026-06-20 | **Milestone:** P1 W0

## Context

ADR-0010 (D10) fixed authn/authz as **local users + OIDC (pluggable)**, short-lived RS256 JWT access tokens, a rotating revocable refresh token, and four RBAC roles (`viewer`/`operator`/`engineer`/`admin`) enforced at the API layer via `require_role(...)` FastAPI dependencies. It deliberately shipped only the local-user path in M0 and recorded the OIDC half as **PROPOSED — Authorization Code + PKCE against an enterprise IdP (Entra ID, Okta, Keycloak), Authlib, IdP group claims mapped to platform roles via a configurable `group → role` table**. That OIDC half is what `PRODUCTION.md` §4 schedules for **P1**, and what `P1-PLAN.md` Wave 2 builds. This ADR is the W0 **design gate** for it: it extends ADR-0010 (never replaces it) and binds the §4 bullets to a concrete, auth-critical design before any Wave-2 code lands.

This is an **identity trust-boundary** decision. The platform holds the keys to routers, firewalls, DDI appliances, and cloud accounts (ADR-0011), and the four-eyes control that makes "the AI changed my firewall" structurally impossible (ADR-0020) is keyed on *who the requester and approver are*. Federating identity to an external IdP moves the authentication trust boundary outside the platform; the subject identity that ADR-0020 compares for four-eyes must therefore be **stable, IdP-anchored, and non-spoofable**. Three CLAUDE.md principles bind hardest here — **"Secure by default"**, **"Enterprise ready"**, **"Audit everything"** — and the platform's **"Local first"** principle requires that federation be *added* without breaking offline/local operation.

Authority honored below: CLAUDE.md (secure-by-default, audit-everything, local-first, enterprise-ready); `DECISIONS-BRIEF.md` D10 (pluggable OIDC, RS256 JWT, four roles), D11 (vault/audit/KeyProvider, no-secret-in-logs), D15 (structlog JSON); `PRODUCTION.md` §4 (the binding scope), §5 (rate-limit/lockout, SIEM, hash-chain), §11 G-SEC (four-eyes on IdP identity, break-glass drill). Prior ADRs extended: **ADR-0010** (the auth foundation), **ADR-0011** (vault + append-only audit), **ADR-0020** (four-eyes spine). No D-decision is deviated from; §1 below makes one ADR-0010 PROPOSED detail (token-validation library / JWKS handling) concrete rather than changing it.

## Decision

**OIDC is a second `IdentityProvider` behind ADR-0010's one interface, implemented as an Authorization-Code-with-PKCE relying party that mints the *same* platform RS256 JWT only after full ID/access-token validation. IdP group claims map to RBAC roles with deny-default (no implicit roles); the platform JWT carries an IdP-anchored, immutable `idp_subject` that is the four-eyes principal (ADR-0020); the local-admin account is retained as audited break-glass; and every failure mode is failure-closed (no token ⇒ no platform session, no role mapping ⇒ no access).**

### 1. Authorization-Code + PKCE flow and token validation

The platform is a **confidential OIDC relying party** (it has a server-side client secret, vault-stored per §6). It runs the Authorization-Code flow with **PKCE (`S256`)** — PKCE is used even though the client is confidential, because it closes the authorization-code-injection class regardless of client type and is mandated by OAuth 2.1.

Flow (all redirect-bearing steps go through `backend/app/core/security/oidc/`, a new module behind the ADR-0010 `IdentityProvider` interface):

| Step | Who | What | Security control |
|---|---|---|---|
| 1. `GET /api/v1/auth/oidc/login` | api | Build authorize URL; generate `code_verifier` (43–128 chars, CSPRNG), `state` (CSPRNG ≥128-bit), `nonce` (CSPRNG ≥128-bit) | `state`+`nonce`+`code_challenge=S256(verifier)` issued together |
| 2. store pending-auth | api | Persist `{state → (code_verifier, nonce, redirect_uri, created_at)}` in a **short-TTL Redis entry** (D8 Redis), TTL ≤ 5 min | server-side only; `code_verifier`/`nonce` **never** leave the server, never in a cookie, never logged |
| 3. redirect to IdP | browser | User authenticates at the IdP | trust boundary crossed here |
| 4. `GET /api/v1/auth/oidc/callback?code&state` | api | Look up pending-auth by `state`; **reject if absent/expired/replayed** (single-use, deleted on first lookup) | CSRF/replay defense — §3 |
| 5. token exchange | api → IdP token endpoint | `code` + `code_verifier` + client secret over TLS (verify on, ADR-0007) | back-channel; secret never in browser |
| 6. validate ID token | api | full validation table below | **fail-closed** on any failure |
| 7. validate/introspect access token | api | signature + `aud`/`iss`/`exp`; use only for IdP-side calls (refresh/userinfo), never as a platform session token | platform never trusts the IdP access token for its own RBAC |
| 8. mint platform JWT | api | issue the **same RS256 platform JWT as ADR-0010 §2** (`sub`, `roles`, `session_id`, `exp`, `iat`, `iss`) **plus** `idp_subject`, `idp_iss` (§2/§4); same 15-min access + rotating refresh-cookie model | platform is the session authority post-login |

**ID-token validation (every check mandatory; any failure ⇒ reject, audit `auth.oidc.login_failed`, no session):**

| Claim / property | Rule |
|---|---|
| signature | Verify against the IdP **JWKS** fetched from the discovery doc (`.well-known/openid-configuration`), matched by `kid`; algorithm pinned to the IdP-advertised asymmetric set (`RS256`/`ES256`), **`alg:none` and HMAC algs rejected** (no `alg` confusion). |
| `iss` | Exact-match the configured issuer for that IdP registration. |
| `aud` | Must contain the platform's `client_id`; reject `azp` mismatch. |
| `exp` / `iat` / `nbf` | Enforced with a **bounded clock-skew leeway of ±120 s** (§3). |
| `nonce` | Exact-match the `nonce` stored in step 2 for this `state`; reject otherwise (anti-replay binding the ID token to *this* login). |
| `sub` (+ `iss`) | The `(iss, sub)` pair is the stable federated identity (§2). |

Token validation uses **Authlib** (ADR-0010 §1 named it for OIDC) for the flow + JOSE primitives, with PyJWT already in the tree for the platform-issued JWT (ADR-0010 §2). This makes the ADR-0010 "implemented with Authlib (PROPOSED)" note concrete; it does not change D10.

### 2. IdP-anchored identity and account linking

A federated user is keyed by the **immutable `(idp_iss, idp_subject)` pair**, not by email or username (email is mutable and re-assignable at the IdP; `sub` is the stable, non-reassigned identifier per OIDC core). The platform `users` table (ADR-0010) gains nullable `idp_iss` / `idp_subject` columns (Alembic expand-migration, ADR-0002 / PRODUCTION.md §10 expand/contract):

- First successful OIDC login for an unseen `(idp_iss, idp_subject)` **provisions** a user row (JIT provisioning), recording `idp_iss`, `idp_subject`, and the display claims (email/name) for UI only.
- Subsequent logins match on `(idp_iss, idp_subject)` and **refresh** the display claims and the mapped roles (§4) from the current token — roles are re-derived every login, never sticky.
- **No email-based linking.** An OIDC identity is never auto-merged into a pre-existing local account by matching email — that would let an IdP-side email change hijack a local-admin row. Account linking, if ever needed, is an explicit admin action, out of P1 scope.

The platform JWT carries `idp_subject` and `idp_iss` as first-class claims so downstream consumers (ADR-0020 four-eyes, audit) read the federated principal directly from the validated session token without a DB round-trip.

### 3. State / nonce / clock-skew / JWKS rotation (security mechanics)

- **`state`** — single-use CSRF token bound to the pending-auth Redis entry; deleted on first callback lookup so a replayed `state` finds nothing and is rejected. Absence ⇒ reject (a callback with no matching pending-auth is treated as forged).
- **`nonce`** — bound into the ID token and re-checked at validation (table §1); defeats ID-token replay across logins.
- **`code_verifier`** — server-held, single-use, never transmitted to the browser; the IdP enforces `S256(code_verifier) == code_challenge`.
- **Clock skew** — `exp`/`iat`/`nbf` validated with a fixed **±120 s** leeway; larger skew is a misconfiguration, not something to tolerate silently (logged at warn). The platform's own 15-min access token (ADR-0010 §2) is unchanged; OIDC skew applies only to IdP-issued tokens.
- **JWKS rotation** — the IdP's signing keys rotate. The platform caches the JWKS keyed by `kid` with a bounded TTL (**PROPOSED 10 min**) and, on encountering an unknown `kid` in an otherwise well-formed token, performs **one** forced JWKS refresh before failing (handles a just-rotated key without a fixed wait), rate-limited to avoid a refresh-storm DoS from forged `kid`s. Discovery doc + JWKS are fetched over TLS (verify on). A JWKS fetch failure is **fail-closed**: logins that need a fresh key are rejected, not waved through.
- **No secret/token in logs** — extends ADR-0011's redaction posture and ADR-0024 §2's "never logged" rule: the client secret, `code_verifier`, raw `code`, ID/access/refresh tokens, and the platform JWT are **never** written to any structlog line (D15), exception message, API response body, reasoning trace, or audit `detail`. The audit events in §5 carry the **`(idp_iss, idp_subject)` identity and an outcome**, never token material. This is a credential-leak G-SEC criterion (PRODUCTION.md §11) and is covered by an explicit leak test in Wave 2.

### 4. IdP group → RBAC role mapping with deny-default

The IdP supplies group/role membership in a configured claim (**PROPOSED claim name `groups`**, per-registration overridable — Entra emits `groups`/`roles`, Okta a custom claim, Keycloak `groups`). A per-IdP-registration **`group → role` map** (the ADR-0010 §1 `group → role` table, realized here) resolves the four platform roles:

| Mapping outcome | Resulting platform authorization |
|---|---|
| One or more groups map to roles | User gets the **union**, collapsed to the **highest** matching role (roles are a total order `viewer < operator < engineer < admin`, ADR-0010 §3). |
| Token carries groups, **none** mapped | **Deny — no session minted.** Unmapped ⇒ no implicit role (deny-default). |
| Token carries **no** groups claim | **Deny.** Absence of authorization data is failure, not "default to viewer". |
| Group maps to `admin` via OIDC | Allowed **only if** the registration's `allow_oidc_admin` flag is true (**PROPOSED default false**); otherwise capped at `engineer`, so production admin stays break-glass-only (§5) unless an operator explicitly federates it. |

**Deny-default is the core security property:** there is **no implicit role**. A federated user with no mapped group is authenticated-but-unauthorized and gets no platform session — failure-closed, not a silent `viewer` fallback. The map is admin-managed config (parity with ADR-0010's role→permission matrix being code/config, not a runtime policy engine), every change is an audited event, and roles are re-derived on **every** login so an IdP-side group removal de-authorizes on next login (within the access-token lifetime, ADR-0010's bounded-revocation tradeoff still applies; full revocation is §5 logout).

### 5. Break-glass local admin, logout/revoke, and audit

- **Break-glass (PRODUCTION.md §4):** with OIDC enabled, the ADR-0010 local-login path is restricted to the **`admin` role only**, is **alerted on every use**, and is audited (`auth.local.breakglass_login`). It is the recovery path when the IdP is unreachable or misconfigured — local-first is preserved (CLAUDE.md). The ADR-0010 §6 bootstrap admin remains this account; it is never disabled, only fenced. A documented break-glass drill is a G-SEC release criterion (PRODUCTION.md §11) and produces an audited, reviewable trail.
- **Token refresh** — two layers, unchanged in spirit from ADR-0010 §2: (a) the **platform** refresh token (rotating, revocable, `HttpOnly; Secure; SameSite=Strict` cookie) refreshes the platform access token without re-contacting the IdP; (b) when the platform refresh token expires, the user re-authenticates — optionally silently via the IdP's existing session (OIDC `prompt=none`), or interactively. The IdP refresh token (if stored) lives **vault-side** (§6), used only server-side to call the IdP, never exposed to the browser.
- **Logout / revoke** — platform logout **revokes the server-side platform session** (refresh-token row marked revoked, ADR-0010 §2 "revocable server-side") so the bounded-revocation window is the ≤15-min access-token life, then clears the cookie. When the IdP advertises an `end_session_endpoint`, the platform also initiates **RP-initiated logout** (redirect with `id_token_hint`) to terminate the IdP session, so a shared-workstation logout is real. **Back-channel logout** (IdP-pushed `logout_token` revoking platform sessions for that `sub`) is **PROPOSED-deferred to P2** alongside SCIM (PRODUCTION.md §4 defers SCIM); P1 covers RP-initiated + platform-side revoke, which meets the §4 "logout revokes platform sessions" exit bar.
- **Audit (ADR-0011 §2, append-only)** — these events are emitted, each carrying actor `(idp_iss, idp_subject)` or `user:<id>` for local, outcome, request id, and **no token material**: `auth.oidc.login_succeeded`, `auth.oidc.login_failed` (with a coarse reason code, never raw claims/tokens), `auth.oidc.user_provisioned`, `auth.oidc.role_mapped` (groups→role decision, group names allowed, tokens not), `auth.local.breakglass_login` (alerting), `auth.logout`, and config-change events for the `group→role` map and IdP registration. Login throttling/lockout (PRODUCTION.md §5, Wave 6 Redis rate-limit) applies to the local break-glass path; the OIDC callback is rate-limited per source to blunt code/`state` flooding.

### 6. Four-eyes on the IdP subject (ADR-0020 extension)

ADR-0020 §3 enforces four-eyes (approver ≠ requester) in the ChangeRequest **service transition guard** for `pending_approval → approved`, backed by a DB constraint trigger on `approvals`, comparing `actor_id` to `change_requests.requester_id` (both FK `users`). PRODUCTION.md §4 and §11 (G-SEC) require this rule to hold on the **IdP identity**, not the local account.

Because §2 anchors every federated `users` row to an immutable `(idp_iss, idp_subject)` and JIT-provisioning is keyed on that pair (one row per federated identity, no email merge), **the existing `requester_id`/`actor_id` user-FK comparison already resolves to the IdP subject** — the platform `user.id` is a faithful 1:1 proxy for `(idp_iss, idp_subject)`. The four-eyes invariant therefore needs **no change to the ADR-0020 guard or trigger**; it inherits correctness from the identity-anchoring in §2. The single hard requirement this ADR adds, to keep that inheritance sound:

> **One federated identity ⇒ exactly one platform user row.** A given `(idp_iss, idp_subject)` must never map to two `users` rows, or two distinct IdP subjects collapse onto one — either would let one human appear as two principals (defeating four-eyes) or two humans as one (blocking a legitimate distinct approval). Enforced by a **`UNIQUE(idp_iss, idp_subject)` constraint** (partial index where `idp_subject IS NOT NULL`, since local users have NULLs), and by the no-email-linking rule (§2). This is the DB-level backstop, in the same defense-in-depth spirit as ADR-0020 §2's constraint trigger.

Vault posture (ADR-0011 §1, ADR-0024 §2): the OIDC **client secret** and any stored IdP refresh token are held as a `credential_ref` to the credential vault (KeyProvider-wrapped), **never inlined** in config, env dumps, API responses, logs, or this ADR. They are materialized in-process only at the moment of a token-endpoint call. No secret value appears anywhere in plaintext at rest outside the envelope-encrypted store.

### 7. Configuration surface (per-deployment, admin-managed)

One or more **IdP registrations**, each: `iss` (discovery base), `client_id`, `client_secret_ref` (vault, §6), `scopes` (`openid profile email groups` — least set for role mapping), `groups_claim` (default `groups`), `group_role_map` (§4), `allow_oidc_admin` (default false, §4), `jwks_cache_ttl` (default 10 min), `clock_skew_secs` (default 120). Enabling OIDC sets the global break-glass fence (§5). All registration/map changes are audited config events (§5). The IdP **test matrix (Keycloak + one cloud IdP) is lab-deferred** to the Wave-2 live run (PRODUCTION.md §4 exit criteria; same deferred-accepted posture as ADR-0024 §6 / P1-PLAN §6) — this ADR fixes the contract the matrix validates.

## Consequences

**Positive**
- Federation is added **without touching ADR-0010's route-level enforcement or ADR-0020's four-eyes guard**: OIDC is a second `IdentityProvider` that mints the *same* platform JWT, so every existing `require_role` dependency, WebSocket upgrade check, and the four-eyes service guard work unchanged — exactly the "slots into enterprise SSO later without touching route-level enforcement" outcome ADR-0010 anticipated.
- **Deny-default + IdP-anchored identity** make the two scariest federation failure modes structurally safe: an unmapped/ungroup'd user gets *no* session (never an implicit role), and four-eyes compares the immutable IdP subject (via the `UNIQUE(idp_iss, idp_subject)` 1:1 row), so SSO cannot let one human masquerade as two approvers.
- **Fail-closed everywhere** (JWKS fetch failure, missing pending-auth, any claim-validation failure, IdP unreachable) means a degraded/attacked IdP path denies access rather than silently weakening it — and **break-glass** keeps the platform operable offline, honoring local-first.
- No token or secret reaches any log/trace/response (extends ADR-0011 + ADR-0024 §2), satisfying the G-SEC credential-leak criterion; secrets stay vault-side as `credential_ref`.

**Negative**
- Two identity paths (local + OIDC) **double the auth and security-review surface** (the cost ADR-0010 already flagged), now including the full OIDC validation table and JWKS-rotation handling — mitigated by the lab-deferred Keycloak+cloud IdP matrix and an explicit leak test, but it is real.
- Role changes at the IdP propagate only at **next login** (roles re-derived per login), so a removed group is still authorized for up to the ≤15-min access-token life — the same bounded-revocation tradeoff ADR-0010 accepted; instantaneous de-authorization would require back-channel logout / token introspection on every request (P2).
- JWKS caching with a forced-refresh-on-unknown-`kid` adds an outbound dependency on IdP availability during login and a small refresh-DoS surface — bounded by the rate-limit on forced refreshes, but a hard IdP outage means OIDC login is down (break-glass is the documented escape).
- **`prompt=none` silent re-auth and back-channel logout are deferred** (P2), so a P1 deployment relying on IdP-session-driven SSO across the platform's 15-min boundary will see interactive re-auth more often than a fully-integrated SSO; acceptable for P1's "login via OIDC end-to-end + logout revokes platform sessions" exit bar.

## Alternatives considered

1. **Trust the IdP's access/ID token directly as the platform session token (no platform-minted JWT).** *Rejected.* It would couple every `require_role` dependency, WebSocket handler, and Celery-dispatched agent job to IdP token formats and remote validation, break offline/local operation (CLAUDE.md local-first), and bypass ADR-0010 §2's revocable refresh model. Minting the same platform JWT after validation keeps the platform the session authority and leaves all downstream enforcement untouched. **Chosen:** platform JWT post-validation (§1).
2. **Key federated identity on email / UPN.** *Rejected, security-critical.* Email is mutable and reassignable at the IdP; an email change could hijack another user's row (including local-admin) and corrupt the four-eyes principal. **Chosen:** immutable `(idp_iss, idp_subject)` with `UNIQUE` constraint and no email-based auto-linking (§2/§6).
3. **Default unmapped IdP users to `viewer` (implicit role) for smoother onboarding.** *Rejected.* It violates deny-default and CLAUDE.md secure-by-default: any authenticated IdP user — including one from a group an operator never intended to grant access — would silently get read access to inventory, topology, and audit data. **Chosen:** deny-default, no implicit role (§4).
4. **Drop the local-admin account once OIDC is enabled (SSO-only).** *Rejected.* An IdP outage or a `group→role` misconfiguration would lock every operator out of a platform that controls production network gear, with no recovery path — and violates local-first. **Chosen:** retain local admin as fenced, alerted, audited break-glass (§5).
5. **Re-anchor ADR-0020 four-eyes on a separate IdP-subject column with its own comparison path.** *Rejected as redundant and riskier.* Because JIT provisioning is 1:1 on `(idp_iss, idp_subject)`, the existing `requester_id`/`actor_id` user-FK comparison already *is* the IdP-subject comparison; adding a parallel path would create two notions of "same person" that could drift (the exact failure ADR-0020 §Alt-4 warns against). **Chosen:** inherit the ADR-0020 guard unchanged, backstopped by the `UNIQUE(idp_iss, idp_subject)` constraint (§6).
6. **Skip PKCE because the client is confidential (server-side secret).** *Rejected.* PKCE closes authorization-code injection independent of client confidentiality and is mandated by OAuth 2.1; the marginal cost is one CSPRNG value per login. **Chosen:** PKCE `S256` always (§1).
7. **Implement the OIDC flow hand-rolled instead of via Authlib.** *Rejected.* Hand-rolling JOSE validation, discovery, and JWKS handling is exactly where auth-critical bugs (`alg:none`, missing `aud`/`nonce` checks, skew) hide; ADR-0010 §1 already named Authlib. **Chosen:** Authlib for the flow/JOSE, PyJWT for the platform JWT (§1).
