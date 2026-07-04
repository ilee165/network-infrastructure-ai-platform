# PR Review — Production Audit **Wave 3: Architecture cleanup**

Branch: `feat/audit-w3-architecture-cleanup` (off `main` @ `f65dfe0`)
Scope: the five Wave 3 work items from
`docs/production-audit-2026-07-01/IMPLEMENTATION_WAVES.md`. One atomic commit per
item. 18 files changed (within the ≤20/wave budget).

## Verification (all green)

| Gate | Result |
|---|---|
| `ruff check .` | All checks passed |
| `ruff format --check .` | 460 files already formatted |
| `mypy` | no issues in 217 source files |
| `lint-imports` (import-linter) | PASS |
| `pytest -n4` (full backend suite) | **3151 passed, 57 skipped, 0 failed** |
| OpenAPI schema (auth split) | **byte-identical** before/after (49 paths) |
| PG-routing heuristic | proven to bite (synthetic `SET LOCAL` diff → exit 1) + clean on this branch |

Frontend untouched (no changes) → frontend suites not exercised.

---

## What changed

### 1. `refactor(auth)` — split `api/v1/auth.py` into a package (ARCH_DEBT #4) · `0443b22`
The 1,608-line `backend/app/api/v1/auth.py` becomes a package of five domain
submodules on one shared `/auth` router:

- `_shared.py` (129) — router, refresh-cookie contract, `_issue_tokens`, `_request_id`
- `login.py` (468) — `POST /login /refresh /logout` + lockout + reuse detection
- `oidc.py` (314) — Authorization-Code + PKCE relying party
- `account.py` (263) — self-service `/me` + sessions
- `users.py` (357) — admin account CRUD
- `settings.py` (154) — admin DB-persisted LLM profile

Pure motion. `__init__` imports submodules in the original route-declaration
order (`login → oidc → account → users → settings`), so route registration order
— and the generated OpenAPI schema — is byte-identical (verified programmatically).
No auth module now exceeds 600 LOC. Zero test edits; the 138-test auth suite
passes unchanged.

### 2. `build(deps)` — lift the `fastapi<0.137` cap (ARCH_DEBT #3) · `9099b68`
`pyproject.toml`: `fastapi>=0.137` (upper cap removed); exact version pinned by
the lockfile. `requirements.lock.txt` regenerated with the **pinned uv 0.11.19**
(the CI-pinned version) — only `fastapi 0.136.3 → 0.139.0` changed.

FastAPI 0.137 made `include_router` lazy (`_IncludedRouter` node, no route
flattening). Two consumers of the old flattened `app.routes` are adapted:
- **`tests/api/test_agents_rate_limit_wiring.py`** — traverses the effective
  route tree via `_IncludedRouter.effective_candidates()` to read each route's
  merged dependant (the include-time rate-limit dependency). Same three
  guarantees.
- **`app/core/metrics_asgi.py` `templated_route()`** — **real runtime regression
  found & fixed.** Under 0.137 `scope["route"]` carries the *router-relative*
  template (prefix stripped), so the Prometheus `route` label lost its `/api/v1`
  mount prefix (`route="/health/live"` instead of `"/api/v1/health/live"`). The
  full templated path is reconstructed by anchoring the router-relative template
  at the **end** of the raw request path — prefix-complete and robust to a param
  value that collides with a static segment.

### 3. `docs(adr)` — ADR-0049 packet-analysis sandbox resolution (ARCH_DEBT #1) · `6ca1aa5`
Decision document only. Resolves the ADR-0031-vs-Celery-runtime contradiction by
**adopting the executor-split** (privilege-light dispatcher + short-lived
fully-seccomp'd capture child), rejecting the weaker-worker alternative. Status
**Proposed**; owner = a named "Packet-Analysis Executor-Split" follow-on wave
(`wf-infra` + `wf-implementer`, strong model, dual-strong security review before
scheduling). Implementation deliberately out-of-wave. Indexed in `docs/adr/README.md`.

### 4. `ci(test)` — PG-test routing heuristic + policy (ARCH_DEBT #2) · `4b20df6`
- `backend/tests/pg/README.md` — the routing rule (PG-semantic code MUST ship a
  `tests/pg/` test), the marker list, the `PG_ROUTING_ALLOW=1` escape hatch, the
  rollout plan.
- `ci/scripts/check-pg-test-routing.sh` — greps the branch diff for PG markers
  (`postgresql_where`, `SET LOCAL`, `pg_advisory*lock`, partition DDL, `NULLS
  FIRST/LAST`, `synchronous_commit`) added to `backend/app` + alembic versions
  with no matching `tests/pg/` change; exits non-zero on a violation.
- `.github/workflows/ci.yml` — new `pg-test-routing` job, **advisory** (not in
  `all-gates` needs) for a one-week false-positive soak; promotion to blocking is
  a one-line `needs` edit (no script change).

### 5. `docs(claude)` — generalize the stale migration-range fact (ARCH_DEBT #8) · `3f072bf`
`CLAUDE.md` hard-coded "revisions `0001`→`0010`"; the chain is at `0015` and
drifts on every migration. Generalized to "migrations are sequential — `upgrade
head` applies the whole `0001`-onward chain."

---

## Risks

| Risk | Severity | Mitigation |
|---|---|---|
| **FastAPI 0.139 behavior drift beyond the two known consumers** | Medium | Full suite (3151) green on 0.139; a repo-wide grep found no other `scope["route"]`/`path_format`/`app.routes` introspection consumers. |
| **`metrics_asgi` route-label reconstruction** is now the SLI label source (P3 W3 SLO/burn-rate alerts depend on it) | Medium | Anchored-suffix reconstruction verified against the existing metrics tests (18) + the two W3-T0 templated-label tests, which were the regression's tripwire. Cardinality guard (`__unmatched__`) preserved. |
| **Wiring test + metrics fix rely on private FastAPI internals** (`_IncludedRouter`, `_EffectiveRouteContext`, `effective_candidates()`) | Low | Pinned by the lockfile; revisited on each deliberate FastAPI bump (documented in both files). `metrics_asgi` uses only public scope keys + `path_format`. |
| **Lockfile determinism** (CI re-resolves on linux with uv 0.11.19) | Low | Regenerated with the exact pinned uv 0.11.19 + `--universal` (host-independent); only the fastapi pin changed. The `lockfile` gate will confirm on CI. |
| **Auth split** hides a behavioral change | Low | OpenAPI byte-identical; 138 auth tests pass with zero edits; `lint-imports` module-boundary contract green. |

## Remaining issues / known limitations

- **`pg-test-routing` is advisory, not blocking**, this PR — by design (one-week
  soak per the audit rollback plan). It will not fail a real PR yet; promotion to
  blocking is a follow-up one-liner once the false-positive rate is confirmed.
- **PG-routing heuristic is a grep, not a proof** — it can miss PG semantics
  expressed without a listed marker, and can false-positive on a marker in a
  comment/string. The `PG_ROUTING_ALLOW=1` hatch and the tests/pg/-changed bypass
  cover the false-positive case.
- **ADR-0049 is Proposed, not Accepted** — it needs the dual-strong security
  review before the implementation wave is scheduled. Packet analysis therefore
  **remains opt-in (default OFF)** until the executor-split ships; no behavior
  change in this PR.
- **The `fastapi` re-review breadcrumb (2026-09-23)** in `pyproject.toml` is now
  obsolete and was removed with the cap; there is no upper bound, so a future
  0.14x that changes internals again would be caught by the wiring/metrics tests
  (and the lockfile keeps the bump deliberate).

## Suggested follow-up work

1. **Promote `pg-test-routing` to blocking** after the soak (add to `all-gates`
   `needs`).
2. **Schedule the Packet-Analysis Executor-Split wave** (ADR-0049) after its
   security review — the last piece to restore "secure by default" for packet
   analysis and re-enable the service.
3. **Broaden the PG-semantics test layer** beyond the P2-W4 controls as new
   PG-specific features land (the heuristic surfaces them; the tests still need
   writing) — closes SQLITE-vs-PG divergence structurally, not just for W4.
4. **CI modularization (ARCH_DEBT #5)** remains out-of-wave — the `pg-test-routing`
   job is one more entry in the 2,000-line `ci.yml`; the standalone DX effort to
   split it is still ledgered.
