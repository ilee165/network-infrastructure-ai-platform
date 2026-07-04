# Architecture Debt & Developer Experience

Production readiness audit, 2026-07-01. Backend: 207 app modules / ~50k LOC; 226 test files / 2,789 tests. This report covers structural debt, dependency posture, test-infrastructure divergence, and DX — items that don't break today but tax every future change.

---

## 1. Packet-analysis service: opt-in default contradicts ADR-0031

> **RESOLVED (2026-07-03, `feat/packet-executor-split`).** Fixed via **option (a),
> the executor-split** — ADR-0049 (Accepted). The Celery dispatcher keeps its
> broker connection under a deny-by-default *dispatcher* seccomp profile and spawns
> a short-lived `python -m app.engines.packet.executor` child per analysis job that
> re-confines with the strict ADR-0031 no-socket profile before parsing the pcap
> (T1/T2), on a dedicated image with tshark + libseccomp (T3). The service is
> **re-enabled by default** (compose `profiles: ["packet"]` removed;
> `packet.analysis.enabled: true` in the chart) gated on the Linux CI bite-proof
> (`packet-analysis-bite-proof`: confined GREEN parse + RED self-test denial with a
> negative control + process-group TIMEOUT kill) green at HEAD (T4). Secure-by-default
> restored without weakening ADR-0031. Historical finding below.

- **Severity:** High
- **Location:** `deploy/docker/docker-compose.yml:112` (`profiles: ["packet"]` — service off by default), `README.md` (packet analysis marked non-functional in the compose quickstart), `deploy/kubernetes/netops/values.yaml` (component gated), vs `docs/adr/0031-packet-sandbox-os-isolation.md`
- **Root cause:** The ADR-0031 seccomp sandbox profile is incompatible with the packet worker's Celery runtime (socket calls the broker connection needs are denied; tempdir/`sem_open` issues were patched in PR #86 but the fundamental worker-in-sandbox contradiction was explicitly deferred). The pragmatic PR #86 decision — gate the service off so the quickstart works — was correct triage, but it leaves a headline capability (CLAUDE.md requires tcpdump/tshark/Wireshark support) shipped dark, and the platform's "secure by default" principle inverted for this one component (the secure profile and the functional service are mutually exclusive).
- **Proposed fix:** Make the design decision explicit rather than residual. Two coherent paths: (a) split the sandboxed capture executor from the Celery consumer — a thin unsandboxed dispatcher process feeds a fully-seccomp'd short-lived capture child (closest to ADR-0031 intent); or (b) write a superseding ADR accepting a broader seccomp allowlist for the worker process with compensating controls (the dedicated node pool + NetworkPolicy already exist). Either way, re-enable the service by default or document opt-in as the accepted end state.
- **Effort:** L (option a) / M (option b)
- **Risk:** Medium — security-relevant design change; needs security review either way.

## 2. SQLite unit suite hides PostgreSQL semantics (recurring bug class)

> **RESOLVED (2026-07-03, audit Wave 3 / PR #108).** Routing rule codified in
> `backend/tests/pg/README.md` (PG-semantic code MUST ship a `tests/pg/` test;
> `PG_ROUTING_ALLOW=1` escape hatch) and enforced by
> `ci/scripts/check-pg-test-routing.sh` via the `pg-test-routing` CI job —
> red-proven on a synthetic `SET LOCAL` diff. The job runs **advisory** during a
> one-week false-positive soak; promotion to blocking (one-line `all-gates`
> `needs` edit) is the remaining follow-up, due ~2026-07-10. Historical finding below.

- **Severity:** Medium
- **Location:** `backend/tests/` (default suite on SQLite) vs `backend/tests/pg/` + `pg-integration` CI job (Postgres-backed, but scoped to the P2-W4 controls)
- **Root cause:** The fast unit suite runs against SQLite; PostgreSQL-only semantics (NULLS-FIRST ordering, partitioned-index rules, `REVOKE`, write-locking, `synchronous_commit`) are invisible to it. This was the *recurring root cause* of the P2-W4 review majors. W5-T0 closed it for the W4 controls with a real PG test layer and a blocking CI job (proven to bite), but the pattern is structural: every new PG-semantic feature (e.g., the P3 audit-export cursor, migration 0014) re-opens the gap unless its tests land in the PG layer.
- **Proposed fix:** Codify the routing rule in `backend/tests/pg/README` + CONTRIBUTING: any code path using PG-specific SQL/semantics MUST ship tests under `tests/pg/`. Add a cheap heuristic CI check (grep for `postgresql_where`, `SET LOCAL`, advisory locks, partition DDL in diffs without matching `tests/pg/` changes) to make omission visible at review time.
- **Effort:** S for the policy + heuristic; ongoing per feature
- **Risk:** Low.

## 3. `fastapi>=0.136,<0.137` upper pin

> **RESOLVED (2026-07-03, audit Wave 3 / PR #108).** Cap lifted — `pyproject.toml`
> now `fastapi>=0.137`, lockfile pins 0.139.0. The route-introspection test was
> adapted to 0.137's lazy `_IncludedRouter` model, and the migration surfaced and
> fixed a real regression: `metrics_asgi.templated_route()` lost the `/api/v1`
> mount prefix in the Prometheus `route` label (the P3-W3 SLO label source). Full
> suite green on 0.139. Historical finding below.

- **Severity:** Medium
- **Location:** `backend/pyproject.toml:20`
- **Root cause:** FastAPI 0.137 changed `include_router` behavior and broke the route-introspection tests (P1-W6 CI saga); the cap was the correct emergency fix, and the lockfile (P3-W0) now prevents silent drift. But an upper pin on the core web framework accrues risk with each upstream release: security patches, Starlette compatibility ranges, and Pydantic interplay all age against a frozen minor.
- **Proposed fix:** Scheduled unpin task: adapt the route-introspection tests to the 0.137+ router model, lift the cap, refresh the lockfile. Should ride the next maintenance wave, not wait for GA.
- **Effort:** M
- **Risk:** Low–Medium — test-surface change, well-bounded.

## 4. `api/v1/auth.py` is a 1,548-line module on a secret-adjacent surface

> **RESOLVED (2026-07-03, audit Wave 3 / PR #108).** Split into the
> `backend/app/api/v1/auth/` package — `_shared` / `login` / `oidc` / `account` /
> `users` / `settings`; largest module is `login.py` at 468 LOC. Pure motion:
> OpenAPI schema byte-identical (49 paths), 138-test auth suite green with zero
> test edits, `lint-imports` module-boundary contract green. Historical finding below.

- **Severity:** Medium
- **Location:** `backend/app/api/v1/auth.py` — largest file in the repo; contains password login + lockout, token mint/refresh/logout, OIDC login/callback/logout federation, user CRUD, session administration, and their helpers.
- **Root cause:** Auth features accreted in one router module across M-auth, W6 (lockout), and OIDC (ADR-0028). Everything in it is security-critical, which makes the oversized review surface itself a risk multiplier: a reviewer paging through 1,500 lines is the audit path for every credential-adjacent change.
- **Proposed fix:** Split along the seams the file already documents: `auth_login.py` (password + lockout), `auth_tokens.py` (refresh/logout/sessions), `auth_oidc.py` (federation), `users.py` (admin CRUD), shared helpers module. Pure motion, no behavior change; keep the router prefix stable.
- **Effort:** M
- **Risk:** Low — mechanical, protected by the existing dense test suite.

## 5. Monolithic 2,020-line `ci.yml` (15 jobs)

- **Severity:** Medium
- **Location:** `.github/workflows/ci.yml` — backend, frontend, security-scan, docker, infra, kind-harness, drill-bite-proofs, kind-harness-ha, kms-emulators, pg-integration, lockfile, observability, all-gates…
- **Root cause:** Every phase added its gate to the single workflow. It works (the gate graph via `all-gates` is sound), but the file is now the highest-conflict artifact in the repo, the inline promotion/deferral commentary (valuable!) is buried among 2k lines, and job-level reasoning is hard to review.
- **Proposed fix:** Split into reusable workflows (`workflow_call`): `ci-core.yml` (lint/test/build), `ci-security.yml`, `ci-kind.yml` (harness + drills), `ci-observability.yml`, orchestrated by a thin top-level file that owns `all-gates`. Preserve the promotion-state comments by moving them next to the jobs they describe.
- **Effort:** M–L (CI refactors need careful staged verification — a gate must be proven to still RUN and BITE after the move, per repo discipline)
- **Risk:** Medium — the known failure mode is a gate silently failing at setup post-refactor; mitigate with deliberate red-then-green proof per moved gate.

## 6. Vendor plugin apply/rollback scaffolding duplicated ~10×

- **Severity:** Low
- **Location:** `backend/app/plugins/vendors/*/plugin.py` (10 vendors, ~10–13k LOC total); identical `except Exception: → rollback` blocks at e.g. `cisco_ios/plugin.py:529`, `cisco_iosxe/plugin.py:414`, `cisco_nxos/plugin.py:501`, `eos/plugin.py:481`, `junos/plugin.py:482`, `fortios/plugin.py:374`
- **Root cause:** The template-following plugin pattern is deliberate (each vendor is independently certifiable, and the conformance suite keeps them honest), but the config-apply/rollback state machine has converged to near-identical code in six SSH-family plugins. A bug fixed in one (as happened with the `is_any` ACL disambiguation class in P2-W3) must be swept across siblings by hand.
- **Proposed fix:** Lift the common apply→verify→rollback driver into `plugins/base.py` with vendor hooks for the command dialect; migrate one plugin per maintenance wave, conformance suite as the safety net. Do **not** big-bang it — certified plugins should churn one at a time.
- **Effort:** L (amortized)
- **Risk:** Medium if rushed; Low at one-plugin-per-wave cadence.

## 7. `GET /api/v1/topology/graph` returns the full projected graph

> **RESOLVED (2026-07-04, audit Wave 5, branch `claude/audit-wave-5-review-1g0o1n`,
> pending merge).** Scoped reads end-to-end: new
> `GET /topology/graph/neighborhood` (device-centered, depth 1–5, Cypher in
> `app.knowledge`), `NETOPS_TOPOLOGY_MAX_NODES` cap on `/graph` (413 problem
> details with guidance to the scoped variants, count pre-check in lockstep
> with the read, 0 disables), and TopologyPage now loads scoped by default
> (site / device-neighborhood picker) with the full-graph fetch explicit and
> server-bounded. Note: `site`/`vrf`/`layer` scoping already existed
> server-side at audit time — the finding's "no scoping parameters" wording
> was imprecise; the real gaps (UI full-fetch default, no neighborhood read,
> no cap) are what Wave 5 closed. Latency assertions at 5,000-device scale
> remain a P5 item with the ADR-0047 seeded dataset. Historical finding below.

- **Severity:** Low (becomes High at scale)
- **Location:** `backend/app/api/v1/topology.py:60` — no scoping/pagination parameters (the only list-shaped endpoint without them)
- **Root cause:** Adequate at lab scale, but the G-SCA gate text itself requires "UI uses scoped queries, no full-graph fetch" at 5,000 devices / 100k interfaces. The scoped-query capability doesn't exist yet, so the frontend necessarily full-fetches.
- **Proposed fix:** Add scoped variants (by site, by device neighborhood at depth N, by overlay type) backed by Neo4j subgraph queries; cap the unscoped endpoint (`max_nodes` + `413`-style problem detail) so it can't be the accidental default at scale. Schedule before the P5 scale certification, not after it fails.
- **Effort:** M–L (API + frontend adoption)
- **Risk:** Low.

## 8. Documentation drift in operating facts

> **RESOLVED (2026-07-03, audit Wave 3 / PR #108).** `CLAUDE.md` migration-range
> fact generalized ("migrations are sequential — `upgrade head` applies the whole
> `0001`-onward chain"); the stale `main.py` placeholder comments were already
> removed in Wave 1 (PR #90). Historical finding below.

- **Severity:** Low
- **Location:** `CLAUDE.md` ("revisions `0001`→`0010` exist" — the repo is at `0014`; similar risk for other frozen facts), stale placeholder comments in `main.py` (see FUNCTIONAL_BUGS #6)
- **Root cause:** Point-in-time facts embedded in standing documents; nothing re-validates them.
- **Proposed fix:** Sweep `CLAUDE.md`/README for numeric facts and either generalize them ("run `alembic upgrade head`; migrations are sequential") or date-stamp them. Cheap, prevents an agent/engineer acting on stale state.
- **Effort:** S
- **Risk:** None.

---

## DX strengths worth preserving (context for the grades)

- **Lockfiles both ecosystems** (`backend/requirements.lock.txt` + blocking `lockfile` CI gate closing the P1 dep-drift TODO; `frontend/package-lock.json` + `npm ci`).
- **Gate discipline:** ruff + mypy + import-linter module-boundary contract + pytest + vitest/eslint/tsc, all blocking; drills designed to *bite* (red-proof before promotion) rather than merely run.
- **Only 1 TODO in 50k backend LOC** (and it's finding #1 in FUNCTIONAL_BUGS) — debt is tracked in docs/ADRs, not scattered in comments.
- **Honest deferral ledger** in `docs/roadmap/PRODUCTION.md` — deferred ≠ dropped, every gap is named. This audit found essentially no *unrecorded* scope gaps, which is rare.
