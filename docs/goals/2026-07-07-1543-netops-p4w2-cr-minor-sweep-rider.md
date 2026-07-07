Rider for docs/goals/2026-07-07-1543-netops-p4w2-cr-minor-sweep-goal.md. Supersedes nothing in prior riders — their invariants still apply (test-only scope, one conventional commit per phase, no schema/behavior change).

## Posture (decided — do not redesign)

- Every anchor below is from PR #119 HEAD (`685b248` on `feat/p4-w2-app-dependency-topology`), pre-merge. After merge to `main`, the same functions/files exist but line numbers may have shifted by a few lines (squash-merge preserves file content; only re-locate if the exact line doesn't match — search by the named function, don't guess).
- Nine items map 1:1 to nine already-posted PR reply comments (deferred-minor disposition) — see PR #119's resolved threads for each item's original CodeRabbit wording and this project's exact reply text.
- CR3 (rejected false-positive) and CR1/CR2/CR6/CR13 (already fixed in `685b248`) are NOT in this sweep — don't re-touch them.
- CR4 (ApplicationsPage lost-update) is explicitly NOT a test gap — do not add optimistic-concurrency (ETag/If-Match/version) code. One doc line only (P10).

## Phases

### P1 — CR5: duplicate-row regression in the dependency list test
File: `backend/tests/api/test_applications.py`, `test_viewer_lists_all_source_rows` (~L591-619, class `TestDependencyListAndDelete`).
Current: `assert {row["source"] for row in rows} == {"manual", "f5"}` — a set comprehension that collapses duplicate rows.
Fix: add `assert len(rows) == 2` immediately before the existing set assertion (two rows seeded: one manual dep via POST ~L596-600, one direct-inserted `ApplicationDependency(..., source=DependencySource.F5)` ~L602-611).
Depth test: extend the existing test in place (same name) — a duplicate-row regression (e.g. a future join fan-out in the list handler) now fails this assertion where it previously wouldn't.

### P2 — CR7: inactive-user 401 parity on the impact endpoint
File: `backend/tests/api/test_impact.py`, `test_impact_endpoint_allows_viewer_and_rejects_anonymous` (~L101-116).
Pattern to mirror exactly: `backend/tests/api/test_adc.py`, `test_inactive_authenticated_user_is_rejected` — uses `auth_headers("inactive")` against a viewer-floor endpoint, asserts 401. The `inactive` user fixture is seeded in `conftest.py` (~L86-93).
Add a new test `test_impact_endpoint_rejects_inactive_authenticated_user` in the same `TestImpactEndpoint` class: authenticated request with `auth_headers("inactive")` against `IMPACT_URL`, assert `401`. Do not fold into the existing test — keep it separately named for clean failure attribution.

### P3 — CR8: untested manual-row guard in the derivation store
File: `backend/tests/engines/topology/test_app_derivation_store.py`, near `test_pass_owns_only_its_source_rows_and_never_manual` (~L239-277).
Production guard: `backend/app/engines/topology/app_derivation_store.py` ~L249-250 — `if source is DependencySource.MANUAL: raise ValueError("derivation plans must never carry manual rows")` inside `apply_derivation_plan`.
Add `test_apply_derivation_plan_rejects_a_manual_source_row`: hand-build a `PlannedDependency` (or whatever the plan's dependency-row type is named at this file's imports) with `source=DependencySource.MANUAL`, call `apply_derivation_plan`, assert `pytest.raises(ValueError, match="must never carry manual rows")`.

### P4 — CR9: migration downgrade drop-order assertion
File: `backend/tests/migrations/test_0018_p4_application_dependency_topology.py`, `test_offline_downgrade_drops_both_tables` (~L144-147).
Current: only checks both `DROP TABLE` strings are present, not their order — but the real `downgrade()` (migration `0018_p4_application_dependency_topology.py`) already drops `application_dependencies` before `applications` correctly (FK direction requires it).
Extend the test: after the existing presence asserts, add
`assert sql.index("DROP TABLE APPLICATION_DEPENDENCIES") < sql.index("DROP TABLE APPLICATIONS")` (match the exact table-name casing the helper's `sql` string uses — check by printing it once if unsure, do not assume case).

### P5 — CR10: missing raw-SQL CHECK-constraint test for `name_not_empty`
File: `backend/tests/pg/test_applications_pg.py`, `test_check_constraints_reject_invalid_values_at_the_db_layer` (~L109-140).
Mirror the existing pattern in the same test (raw `text()` INSERT bypassing the app-layer StrEnum, for `origin`/`target_kind`/`source`) to add a `name=''` case exercising migration's `length(name) > 0` CHECK (migration line ~71 / model `applications.py` ~L110): `INSERT INTO applications (..., name, ...) VALUES (..., '', ...)`, assert `IntegrityError`/`DBAPIError`, roll back. This file requires the real Postgres service (`pytestmark = pytest.mark.integration`, already set from the earlier `34774b7` fix) — run with `NETOPS_TEST_DATABASE_URL` pointing at a reachable Postgres, or accept the clean skip if none is available and note that in the phase commit.

### P6 — CR11: app-dependency panel must NOT render outside the app layer
File: `frontend/src/__tests__/TopologyAppLayer.test.tsx` (~L166; production guard: `frontend/src/pages/TopologyPage.tsx` ~L677, `layer === "app" && data`).
Every existing test clicks `topology-layer-app` before asserting the panel appears — none proves it's ABSENT otherwise. Add `does_not_render_the_app_dependency_panel_outside_the_app_layer`: render with the default (`all`) layer active (no click), assert `screen.queryByTestId("app-dependency-panel")` is `null`. Optionally repeat for `l2`/`l3`/`dns` if the harness makes it cheap; the `all`-layer case alone satisfies the finding.

### P7 — CR12: malformed `properties.sources` fixture
File: `frontend/src/__tests__/TopologyAppLayer.test.tsx` (~L165; production fallback: `TopologyPage.tsx` ~L79-82, `edgeSources` falling back to `[]` when `sources` isn't an array).
Add a `DEPENDS_ON` edge fixture with `properties.sources` either omitted or set to a non-array (e.g. a bare string), assert the app-dependency panel / edge badge renders with zero source badges rather than throwing.

### P8 — CR14: `f5_pools_missing` stat never exercised
File: `backend/tests/engines/topology/test_app_derivation.py`, near `test_f5_unreconcilable_member_emits_no_edge_but_is_counted` (~L334-343).
Production: `app_derivation.py` ~L392-395 — `pool = pool_by_key.get((...)); if pool is None: pools_missing += 1; continue`.
Add `test_f5_missing_pool_emits_no_edge_and_increments_f5_pools_missing`: build a virtual server whose `pool_name` points at a key absent from `pool_by_key` (i.e. no matching `make_pool(...)` seeded), assert no F5 edge is emitted for that app and `plan.stats.f5_pools_missing == 1`.

### P9 — CR15: rejected-mutation error-rendering coverage
File: `frontend/src/__tests__/ApplicationsPage.test.tsx` (~L277-379).
All current create/edit/delete/add-dependency/remove-dependency tests stub a successful `fetch`. Add at least one rejected-mutation case per surface (`ApplicationFormModal` create-or-edit, `DependencyAddForm`, the delete `ConfirmDialog`) — stub `fetch` to resolve a 409 or 500 for the relevant POST/PATCH/DELETE, assert the component's `role="alert"` error text renders (`formError` / `confirmError`, per the existing component prop names). One test per surface is enough; don't attempt every status code.

### P10 — CR4: tracked doc note (no code change)
File: `docs/roadmap/p4-tasks/W2-T3-manual-application-tagging.md`, `## Risks` section.
Add one entry: the `ApplicationsPage` edit mutation sends a full snapshot (all fields) rather than a partial diff, so a concurrent edit by another user is last-write-wins; fixing it needs backend optimistic-concurrency (ETag/`If-Match`/version or an `updated_at` precondition) that the API doesn't expose today — tracked as a follow-up, not implemented this round (PR #119 CR4). Keep it to 2-3 sentences; do not expand the Risks section's existing structure or renumber other entries.

### P11 — Close-out (no depth test)
Full backend gate suite (`pytest`, `ruff check .`, `ruff format --check .`, `mypy`, `lint-imports`) and full frontend gate suite (`npm run test`, `npm run lint`, `npm run typecheck`) green in one final transcript run. Confirm `git diff --stat -- docs/roadmap/p4-tasks/W2-T3-manual-application-tagging.md` shows only the P10 addition. Report the 9 new test names + the CR4 note as the round's summary.

## Out of scope

- Any implementation of optimistic concurrency for CR4 (design addition, not this sweep's scope).
- Re-opening CR3 (already rejected as false-positive) or re-touching CR1/CR2/CR6/CR13 (already fixed).
- New CI wiring, new markers, new test directories — every item lands inside its existing test file.

## Dependencies

- Tier 1/2/3: none. Every phase adds tests inside existing files using already-imported fixtures/helpers (`auth_headers`, `pg_session`, `make_pool`/`make_vs`, RTL `screen`/`waitFor`) — no new package in `backend/pyproject.toml` or `frontend/package.json`.

## Engineering invariants

- No production code changes except the single CR4 doc line (P10) — every other phase is test-only.
- Each new test must be red without its corresponding production behavior and green with it (verify by a quick local revert-and-rerun if the behavior is cheap to toggle; skip the revert check only where it's clearly redundant, e.g. P1/P4's presence-order assertions against already-correct code).
- Don't weaken any existing assertion while adding a new one (e.g. P1 adds `len(rows) == 2` alongside, not instead of, the existing set assertion).

## Process invariants

- One conventional commit per phase (P1-P10), body ending `(rider PN)`; P11 is the close-out, no new commit required unless the gate run itself needed a fixup.
- If any anchor's line number or symbol name has drifted from what's cited here (post-merge), re-locate by test/function name and note the actual location in that phase's commit message — don't guess or skip the item.
