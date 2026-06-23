# API Rate Limiting + Login Throttle / Lockout

**Task:** P1 W6-T6 · **ADRs:** ADR-0008 (Redis), ADR-0010 (auth/JWT), ADR-0011 §2
(audit), ADR-0028 §2/§5 (OIDC callback throttle, break-glass) · **PRODUCTION.md:**
§5, §11 G-SEC / G-SCA

This closes the PRODUCTION.md §5 line: *"API rate limiting — Redis-backed,
per-user and per-token — and login throttling/lockout."* All counters live on the
**shared Redis** (ADR-0008) so a limit holds across `api` replicas (D13) rather
than resetting per pod or diverging between pods.

## What is enforced

| Control | Key (per) | Default budget | Response when exceeded |
|---|---|---|---|
| **API request rate limit** | `user:<id>` **and** `token:<jti>` | 120 req / 60 s | `429` + `Retry-After` |
| **Login throttle / lockout** (local break-glass) | account **and** source IP | 5 fails / 300 s ⇒ lock 900 s | `429` + `Retry-After` |
| **OIDC callback rate limit** | source IP | 30 / 60 s | `429` (generic OIDC failure) |

The API limit is applied as a **route dependency** (`enforce_api_rate_limit`),
attached to each protected route rather than as a single router-level middleware
(`backend/app/api/deps.py`, wired in `backend/app/api/v1/__init__.py`). For most
routers it is supplied once via `include_router(..., dependencies=[...])`, which
FastAPI binds onto every route in that router; the `agents` router instead lists
it per `@router.get/post` (`agents._API_RATE_LIMIT`) so its `@router.websocket`
streaming route — whose `HTTPBearer` dependency cannot resolve on a WebSocket
scope — is left unbound. It is **not** applied to the unauthenticated health
probes (they carry no principal and must never be throttled) nor to the `auth`
router (the login path has its own throttle/lockout, and the bearer-keyed API
budget would double-count token-bearing `refresh`/`me` calls).

The OIDC **callback** throttle is distinct from the **forced-JWKS-refresh**
rate-limit (ADR-0028 §63, implemented in `app.core.oidc.JwksCache`): the former
caps callback *hits* per source to blunt `code`/`state` flooding; the latter caps
forced JWKS refreshes per issuer to blunt a forged-`kid` refresh storm. They are
coordinated, not duplicated.

## Fail-mode decision (explicit, both tested)

A Redis blip must not become an availability **or** a security footgun, so the two
controls fail in **opposite** directions on a backend outage:

- **API rate limiter — FAIL OPEN.** Availability wins: a degraded limiter must not
  take the API down. If Redis is unavailable the request is served. (An
  un-throttled authenticated request is still fully authenticated/authorized.)
- **Login lockout — FAIL CLOSED / CONSERVATIVE.** Security wins: do **not** hand
  out unlimited login attempts because Redis blipped. If the lockout backend is
  unavailable the login attempt is refused (`429`) — even for a correct password —
  rather than waved through. Break-glass remains recoverable once Redis returns.
- **OIDC callback throttle — FAIL OPEN.** A limiter outage must not break
  legitimate SSO; the §3 fail-closed claim-validation still gates every callback,
  so an un-throttled callback cannot itself mint a bad session.

Both fail-modes are asserted in the test suite
(`tests/api/test_rate_limit_api.py::test_api_limiter_fails_open_on_backend_outage`
and `tests/api/test_login_lockout.py::test_lockout_fails_closed_on_backend_outage`).

## No account-existence leak (no oracle)

A throttled or locked response never discloses whether the username exists: the
locked-login `429` is identical (status, generic detail, coarse `Retry-After`) for
a real account and an unknown username. `Retry-After` is **coarse** (the whole
remaining window / lockout duration, never a precise per-key countdown) so it
cannot be used as a timing oracle.

## Audit (no token material, no raw claims)

Two append-only audit actions are emitted (ADR-0011 §2), mirroring the existing
`auth.login_failed` posture — actor + source + outcome + request id only, and
**never** any token bytes, `jti`, password, or raw claims:

- `auth.rate_limited` — an API request or OIDC callback turned away for exceeding
  its budget. `actor` is `user:<id>` (or `oidc:source:<ip>` for the callback);
  `detail` is `{source, outcome: "rate_limited"}`.
- `auth.login_locked` — the temporary, alerting-friendly break-glass lockout once
  the failed-attempt threshold is crossed. `actor` is the attempted username;
  `detail` is `{source, outcome: "locked"}`. Break-glass logins already alert
  (ADR-0028 §5), so a lockout is both audited and operator-visible.

## Performance (G-SCA)

Each check is **O(1)** on Redis (one `INCR` plus one `EXPIRE` on the first hit of
a window; a single `GET` for the lockout peek) and is keyed by principal / token /
source — there is **no single global hot key** to contend on, so the limiter does
not become the bottleneck under the §11 G-SCA load shape (100 concurrent users,
p95 < 300 ms). Counters carry a TTL and auto-expire; a counter that lost its TTL
(e.g. a crash between `INCR` and `EXPIRE`) is re-armed so it can never become a
permanent lock.

## Configuration knobs (secure defaults)

All `NETOPS_`-prefixed environment variables (`app/core/config.py`):

| Setting | Default | Meaning |
|---|---|---|
| `rate_limit_requests` | `120` | Authenticated API requests per window, per principal/token |
| `rate_limit_window_secs` | `60` | API rate-limit window length |
| `login_lockout_threshold` | `5` | Failed logins (per account+source) before lockout |
| `login_lockout_window_secs` | `300` | Window over which failed logins accumulate |
| `login_lockout_duration_secs` | `900` | Temporary lockout duration once tripped |
| `oidc_callback_rate_limit` | `30` | OIDC callbacks per window, per source |
| `oidc_callback_window_secs` | `60` | OIDC callback rate-limit window length |

## Wiring

- Production binds `RedisRateLimiter` (over the shared `redis_url`) on
  `app.state.rate_limiter` at startup (`app/main.py` lifespan). The Redis client is
  lazy, so a brief Redis outage at boot is tolerated (the fail-modes above apply).
- Tests / single-process / local-first runs fall back to a process-local
  `InMemoryRateLimiter` (same fixed-window semantics, no broker).
- The raw `redis` SDK exception is never surfaced: `RedisRateLimiter` wraps any
  backend failure in a typed `RateLimitBackendError` whose message carries no DSN
  or credential material.
