# W6-T6 — Redis-Backed API Rate-Limit + Login Throttle / Lockout

| | |
|---|---|
| **Wave** | P1 W6 — Security hardening (P1 subset) |
| **Owner** | `wf-implementer` (strong — Python, auth-surface) |
| **Review tier** | **strong** spec + **strong** quality (auth/secret-surface escalation, P1-PLAN.md §3) |
| **Depends on** | — (independent of the KMS + CI streams; touches auth/middleware) |
| **ADRs** | ADR-0010 (auth, JWT), ADR-0028 §2 (OIDC callback throttling; break-glass lockout), ADR-0008 (Redis), ADR-0011 §2 (audit) |
| **PRODUCTION.md** | §5 ("API rate limiting — Redis-backed, per-user and per-token — and login throttling/lockout"), §11 G-SEC / G-SCA |
| **Status** | Proposed |

## Objective

Add Redis-backed **API rate limiting** (per-user and per-token) and **login throttling / lockout**
to the FastAPI app, closing the PRODUCTION.md §5 line. Login throttle/lockout applies to the local
**break-glass** path and the **OIDC callback** per source (ADR-0028 §2), with every limit/lockout
event audited and no information leak about account existence.

## Scope

**In** (`backend/app/api/…` middleware/deps, `backend/app/api/v1/auth.py`, Redis)
- **API rate limiting**, Redis-backed, **per-user and per-token** (PRODUCTION.md §5): a sliding/fixed
  window counter keyed by authenticated principal (`user:<id>`) and by token id, returning **HTTP
  429** with a `Retry-After` when exceeded. Reuse the D8 Redis (ADR-0008) already in the stack.
- **Login throttling + lockout** on the **local break-glass** login path: progressive throttle then
  temporary lockout after N failed attempts within a window; lockout is per-account + per-source.
- **OIDC callback rate-limit per source** (ADR-0028 §2/§84): blunt code/`state` flooding; the forced
  JWKS-refresh path is already rate-limited (ADR-0028 §63) — coordinate, don't duplicate.
- **Audit** (ADR-0011 §2, append-only): emit limit/lockout events (e.g. `auth.rate_limited`,
  `auth.login_locked`) carrying actor (attempted username / `user:<id>`), source, outcome, request
  id — **no token material, no raw claims**, consistent with the existing `auth.login_failed`
  posture (ADR-0028 §84).
- **No account-existence leak**: a throttled/locked response must not disclose whether the username
  exists (mirrors the existing `auth.py` "neither target nor detail discloses whether the user
  exists" posture).
- Config knobs (limits, windows, lockout threshold/duration) with secure defaults; documented.

**Out**
- KMS / rotation (W6-T1..T3) and CI supply-chain (W6-T4/T5).
- Per-credential device-secret rotation; WAF / edge rate-limiting (infra concern, not this task).
- The four-eyes / RBAC logic (M5/W2) — unchanged; this task is throttle/lockout only.

## Requirements (grounded in PRODUCTION.md §5, ADR-0028 §2, ADR-0010)

1. **Redis-backed, per-user and per-token** (PRODUCTION.md §5): limits are enforced on the shared
   Redis so they hold across `api` replicas (D13 multi-replica) — not in-process counters that reset
   per pod or diverge across replicas.
2. **Login throttle/lockout covers the local break-glass path** (ADR-0028 §84): break-glass is the
   high-value local credential; brute-force protection here is the point. Lockout is temporary +
   audited + alerting-friendly (break-glass logins already alert, ADR-0028 §84).
3. **OIDC callback per-source rate-limit** (ADR-0028 §2): blunt `code`/`state` flooding without
   breaking legitimate logins; fail-closed on the auth path stays as ADR-0028 specifies.
4. **Fail-mode decision is explicit**: on Redis unavailability, **API rate-limiting fails open**
   (availability — a degraded limiter must not take down the API), but **login lockout fails
   closed/conservative** (security — do not hand out unlimited login attempts because Redis blipped).
   State and justify this in the spec/tests (secure-by-default bias on the auth path).
5. **No leak** (ADR-0011 §6 / existing auth posture): no token material in logs/audit; responses
   don't disclose account existence; `Retry-After` is coarse.
6. **G-SCA-aware**: the limiter must not become the bottleneck under the §11 G-SCA load test
   (100 concurrent users, p95 < 300 ms) — O(1) Redis ops, no hot-key contention on a single global key.

## Contracts / artifacts

- A rate-limit dependency/middleware (`app/api/deps.py` or `app/api/middleware/…`) applied to the
  API + auth routers; keying by principal + token id; 429 + `Retry-After`.
- Login throttle/lockout in `app/api/v1/auth.py` (local break-glass) + OIDC callback per-source limit.
- `audit_log` emitters `auth.rate_limited` / `auth.login_locked` (ids/source/outcome only).
- Settings (`app/core/config.py`): window/limit/lockout knobs with secure defaults.
- Docs: rate-limit/lockout behavior + fail-mode rationale (CLAUDE.md documentation standard).

## Test & gate plan (Python TDD — D16)

- ruff / mypy strict / import-linter / pytest ≥80% on touched modules.
- Rate-limit: N+1th request in a window ⇒ 429 + `Retry-After`; counters keyed per-user **and**
  per-token; limits hold across simulated multi-replica (shared Redis / fakeredis).
- Login lockout: N failed break-glass attempts ⇒ temporary lockout; lockout audited; response does
  **not** disclose account existence; lockout expires after the window.
- OIDC callback flooding ⇒ throttled per source without blocking a legitimate callback.
- Fail-mode: Redis down ⇒ API limiter fails open (requests served); login lockout fails
  conservative (no unlimited attempts) — both asserted.
- No-leak: no token material in audit/logs; 429/lockout responses coarse.

## Exit criteria

- [ ] Redis-backed API rate limiting, per-user **and** per-token, 429 + `Retry-After`, holding across
      replicas (G-SEC, G-SCA).
- [ ] Local break-glass login throttle + temporary lockout, audited, alerting-friendly; OIDC callback
      per-source throttle.
- [ ] No account-existence leak; no token material in logs/audit.
- [ ] Explicit fail-modes: API limiter fail-open, login lockout fail-conservative — both tested.
- [ ] Limiter is O(1)/non-contended (G-SCA-safe); behavior + fail-mode documented; D16 gates green.

## Workflow (P1-PLAN.md §3, auth-surface escalation)

`wf-implementer` (strong) implements → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** in parallel → `wf-fixer` (strong) if findings → `wf-verifier` → **one atomic commit**.

## Risks

- Wrong fail-mode choice is a security or availability footgun (Redis blip ⇒ either lockout-bypass or
  API outage) — the explicit fail-open-API / fail-conservative-lockout split + its tests are the
  guardrail.
- A global hot key would make the limiter a G-SCA bottleneck — key by principal/token, not one
  counter, and verify under the load-test shape.
