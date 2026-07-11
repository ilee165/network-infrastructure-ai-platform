# Cross-wave lessons learned

Living log of concrete, repo-specific traps that already cost a CI red or a
review round. Wave-scoped retros also live alongside plans (e.g.
`P1-W4-LESSONS.md`); **new standing rules that apply to every phase land here
and in `CLAUDE.md`**.

Each lesson: **what bit us → why → the rule for next time → who it hits next.**

---

## Frontend / SPA

### L-FE-1 — Partial `vi.mock` of an API module must list every export the tree imports

**Bit us:** Settings hub Path A (PR #125) added `getRotationStatus` on
`frontend/src/api/credentials.ts` and wired it into `SettingsCredentialsSection`.
`SettingsPage.test.tsx` was updated; **`SettingsRoute.test.tsx` was not**. CI
frontend job failed with:

```text
[vitest] No "getRotationStatus" export is defined on the "../api/credentials" mock.
Did you forget to return it from "vi.mock"?
```

Same class of risk for `getOidcStatus` on the auth mock when Access mounts.

**Why:** Vitest replaces the whole module with the mock factory return value.
Any new named import from a partially mocked module is missing unless the
factory exports it — and the failure only appears when a test *mounts* a
component that imports the new symbol (page tests can pass while route-gate
tests go red).

**Rule:**

1. When adding a public export to `frontend/src/api/*`, **grep** for
   `vi.mock("../api/<module>"` / `vi.mock('../../api/<module>'` and update
   **every** mock factory.
2. Prefer the same default-resolved shape the real client returns so
   `useQuery` does not hang on pending forever.
3. Run the sibling suites before push: page + route + layout tests that
   import the same section components.

**Hits next:** Any Settings / inventory / topology PR that grows an API client
used under nested routes or shell queries.

**Evidence:** PR #125 CI run (frontend fail); fix commit
`cf54ac5` (`SettingsRoute.test.tsx` mocks).

---

## Images / supply chain

### L-IMG-1 — Fixable Alpine CVE + GHA layer cache: bump `apk upgrade` cache-bust, do not ignore

**Bit us:** Same PR #125 docker job: Trivy image scan on `netops-frontend:ci`
failed **HIGH** on `c-ares` **CVE-2026-33630** (`1.34.6-r0` → fixed in
`1.34.8-r0`). The Dockerfile already runs `apk upgrade --no-cache`, but CI
`cache-from/to type=gha` reused the **stale** upgrade layer dated
`2026-07-08`, so the patched package never entered the image.

**Why:** `apk upgrade` is only as fresh as the last uncached layer. A date
comment is the intentional cache-bust (documented in
`deploy/docker/frontend.Dockerfile`). Ignoring a *fixable* CVE in
`.trivyignore-image` would green the gate without shipping the patch.

**Rule:**

1. On Trivy RED for a **fixed** Alpine (or similar) package in the frontend
   (or any) image: **bump the cache-bust date/comment** on the
   `apk upgrade` (or equivalent) `RUN` so the layer rebuilds.
2. Prefer upgrade over pin-and-ignore. Use `.trivyignore-image` only for
   reviewed **unfixed** or accepted residual findings with expiry (see
   `docs/security/image-supply-chain.md` §4).
3. After the bump, confirm the docker job’s Trivy step is green — that is
   the “gate RUN and BITE” proof that the new packages landed.

**Hits next:** Every PR that builds `deploy/docker/frontend.Dockerfile` (and
any future image stage that relies on periodic `apk`/`apt` upgrade + GHA
layer cache).

**Evidence:** PR #125 docker fail (c-ares 1.34.6-r0); fix commit `cf54ac5`
(cache-bust `2026-07-10`).

---

## Backend / async / review hygiene

### L-ASYNC-1 — After `session.rollback()`, never touch expired ORM attributes

**Bit us:** Wave 2 devices IntegrityError handler did
`updates.get("mgmt_ip", device.mgmt_ip)` **after** `await session.rollback()`.
On async SQLAlchemy that lazy-loads expired attrs and can raise
`MissingGreenlet` (or silently mis-report). CodeRabbit flagged on PR #141.

**Rule:** Snapshot any fields needed for the error message **before**
`flush`/`rollback`. Prefer request-body values (`body.mgmt_ip`) over
re-reading the expired instance.

**Hits next:** Any create/update path that maps `IntegrityError` → 409.

### L-CYPHER-1 — Never `MATCH (n) OPTIONAL MATCH ()-[r]->()` for dual counts

**Bit us:** Wave 2 `graph_freshness` used one Cypher with both clauses;
`count(r)` becomes **N×E** (Cartesian), so the topology edge gauge was wrong
on every healthy no-op tick — worse than hard-coding 0.

**Rule:** Aggregate nodes and edges in **separate** queries (or a pattern that
binds `r` to `n`). Add a source-shape regression if the query is easy to
re-break.

**Hits next:** Any Neo4j metric / freshness / inventory count path.

### L-CURSOR-1 — Offset cursors skip interleaved ordered inserts

**Bit us:** WS durable replay used `OFFSET emitted` on steps ordered by
`(trace.started_at, id, ordinal)`. Concurrent specialist traces can insert a
step that sorts **before** already-emitted later rows; offset then **skips** it
forever (dedupe keys cannot recover a never-loaded row).

**Rule:** For multi-writer ordered streams, either load all rows and dedupe by
stable key, or use a **seek cursor** on a monotonic unique key — not a pure
offset into a reorderable list.

**Hits next:** Any poll/replay over multi-trace or multi-shard ordered data.

### L-IDEM-1 — Idempotent insert must return created vs existing for audit

**Bit us:** Packet `ON CONFLICT DO NOTHING` returned the existing row, but
the worker still wrote `packet.capture_completed` — concurrent redelivery
could double-audit even when the row was unique.

**Rule:** Claim/upsert helpers return `(row, created: bool)`; emit
started/completed audits **only** when `created`. Assert audit row counts in
redelivery tests, not only side-effect counters.

**Hits next:** Celery `acks_late` / claim-before-work tasks (config backup
pattern is the precedent).

### L-CI-1 — Always `ruff check` on **new** test files before push

**Bit us:** PR #141 backend job failed only on `tests/core/test_security_async.py`
(I001 import order + F401 unused `asyncio`) written via shell heredoc without
ruff.

**Rule:** After adding any new module/test: `ruff check <path> --fix` and
`ruff format`. New files are the highest-risk for unrun lint.

**Hits next:** Every wave that scaffolds tests with write tools / shell.

### L-TEST-1 — Do not duplicate production mappings in FE tests

**Bit us:** `discovery-partial-status.test.tsx` re-declared `RUN_VARIANT`
locally; production could drop `"partial"` and the test stayed green.

**Rule:** Export the production map (or render the real page with fixtures)
and import it in the test. Vacuous `if (found)` guards around expects are
also forbidden — assert presence first.

**Hits next:** StatusPill / enum drift tests.

---

## Dependencies / Dependabot

### L-DEP-1 — Dependabot lock-only majors that full `uv` recompile reverts are unmergeable

**Bit us:** Dependabot opened pip majors that surgically rewrote one pin in
`backend/requirements.lock.txt`:

- #149 `redis` 6.4.0 → 8.0.1 — blocked by `kombu[redis]` (`redis<6.5`)
- #146 `paramiko` 4.0.0 → 5.0.0 — blocked by `netmiko` (`paramiko<5`)
- #151 `websockets` 15.0.1 → 16.0 — blocked by `langgraph-sdk` (`websockets<16`)

The CI **lockfile** job re-runs `uv pip compile` from `pyproject.toml` and
reverted each pin → `all-gates` RED. Green minors/patches in the same batch
(#148 uvicorn, #150 wcwidth, npm/GHA) were fine.

**Why:** A single-line lock edit is not a full resolve. Transitive upper bounds
make the major impossible until the constraining package is upgraded first.

**Rule:**

1. If lockfile RED and recompile reverts the pin → **confirmed constraint
   conflict only** — close and `@dependabot ignore this major version`, or keep
   a scoped ignore in `dependabot.yml` that cites the constrainer. Do **not**
   force-edit the lock to green. Do **not** use close+ignore for planned
   migrations without a constraint conflict (ignore is forward-suppressing and
   blocks later security updates for that major). For planned migrations: close
   *without* ignoring, or a tracked scoped ignore with owner + revisit date.
2. Human major upgrades: lift the constrainer in `pyproject.toml`, re-lock with
   `--upgrade-package`, run integration, land as a normal PR.
3. Schedule is **monthly**; pip majors for `redis` / `paramiko` / `websockets`
   are scoped-ignored. Never blanket-ignore `*` majors (suppresses security
   updates — PR #142).

**Hits next:** Any Dependabot pip PR that only touches `requirements.lock.txt`
with a major bump.

**Evidence:** Closed #146/#149/#151; triage SOP in
`docs/security/supply-chain-scanning.md` (“Dependabot triage (monthly)”).

---

## Related

| Doc | Scope |
|---|---|
| `CLAUDE.md` § Orchestrated builds / Build & runtime | Standing agent rules (includes L-FE-1 / L-IMG-1 one-liners) |
| `P1-W4-LESSONS.md` | Helm/K8s GA chart wave (L1–L8) |
| `docs/security/image-supply-chain.md` | Trivy / SBOM / cosign / admission controls |
| `docs/security/supply-chain-scanning.md` | Lockfile gate + Dependabot triage (L-DEP-1) |
| `deploy/docker/frontend.Dockerfile` | `apk upgrade` cache-bust comment mechanism |
| `docs/reviews/WAVE2-PLAN.md` / PR #141 | Source of L-ASYNC-1 … L-TEST-1 |
