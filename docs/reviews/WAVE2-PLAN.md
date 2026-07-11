# Wave 2 Implementation Plan — Small Bugs + Perf Quick Wins

Parent plan: [`REVIEW-WAVES-PLAN.md`](REVIEW-WAVES-PLAN.md). Source findings:
[`2026-07-10-repo-review.md`](2026-07-10-repo-review.md) (H/M IDs),
[`PERF-REVIEW-2026-07-10.md`](PERF-REVIEW-2026-07-10.md) (perf ranks / quick wins),
[`2026-07-10-testing-strategy-review.md`](2026-07-10-testing-strategy-review.md) (F IDs).

**Shape:** one branch (`fix/review-wave2`), one PR, one atomic commit per task.
Every fix lands with a regression test that fails before / passes after.
Zero behavior change beyond the stated fix. New CI steps must prove they bite
(plant violation → RED → revert → GREEN; run URLs in PR body). Dependency
additions regenerate the lockfile in the same commit.

**Scope guard:** no refactors beyond the named extraction (T11); SettingsPage
split stays deferred; nothing here touches the config-write transport (Wave 3)
or drift gates (Wave 4).

---

## Group A — Backend correctness (repo-review HIGHs)

### T1 — H1: mgmt_ip unique-race returns 500 instead of 409
`backend/app/api/v1/devices.py:168,199`. Create/update flushes lack an
`IntegrityError` guard (delete at `:225` has one); concurrent same-`mgmt_ip`
writes pass `_ensure_mgmt_ip_free` then die as unhandled 500.
- Fix: wrap both flushes; `IntegrityError` → `ConflictError`, mirroring the
  already-fixed `applications.py:315,377,510` precedent.
- Test: simulate the race (flush raising `IntegrityError`) → assert 409 on
  create and update paths.

### T2 — H5: firewall management-plane check misses `services=("any",)`
`backend/app/engines/security/firewall.py:302-304`. Exact-name intersection
means a wildcard-service rule from `source=any` never fires the HIGH
management-plane finding — false negative in a trusted-signal tool.
- Fix: when the services/applications dimension is `any`, treat `exposed` as
  the full `MANAGEMENT_SERVICES` set.
- Test: `any`-service + `any`-source rule yields the HIGH management-plane
  finding; existing precision corpus (P2-W5-T1) stays green.

### T3 — H6: auto-rebuild steady-state ticks force edge gauge to 0
`backend/app/engines/topology/auto_rebuild.py:165-167`. No-op reconcile
hard-codes `edges=0` into `observe_rebuild` + metrics textfile;
`topology_rebuild_edges` (consumed by DR/RTO drill + G-OBS SLO) reads 0 in the
healthy common case.
- Fix: query live edge count on the no-op path (extend `graph_freshness`), or
  carry forward the last real gauge value.
- Test: no-op tick emits the true edge count, not 0.

### T4 — H13: exception `detail` bypasses A9 redaction chokepoint
`backend/app/agents/framework/tools.py:538` vs `:383`. `_emit` redacts
`arguments` but persists `detail=str(exc)` raw; Pydantic `ValidationError`
text embeds offending input values → secret in a mistyped tool arg lands
unredacted in the durable audit log.
- Fix: route `detail` through `redact_payload`/`redact_prompt` (or the
  `security/tools.py::_sanitized_validation_error` approach) inside `_emit` so
  every emit site is covered.
- Test: tool raising `ValidationError` containing a secret-shaped value →
  persisted detail is redacted.

### T5 — H9: SpatiumDDI `AsyncClient` bound to a dead event loop
`backend/app/plugins/vendors/spatiumddi/plugin.py:200` + `client.py:104`.
Each capability call runs a fresh `asyncio.run()` loop but the single
`AsyncClient` from `__init__` pins its httpcore pool lock to the first loop —
second read on a device session raises `RuntimeError` in production. Invisible
under `MockTransport` (no pool).
- Fix: one event loop per device session, or fresh client per `_run`
  invocation.
- Test: two sequential capability calls on one session succeed (a test shape
  that exercises real loop teardown, not `MockTransport`-only).

### T6 — H10: packet capture tasks not idempotent under redelivery
`backend/app/workers/tasks/packet.py:382`, `engines/packet/capture.py:279`,
`celery_app.py:102-107`. `task_acks_late` + `task_reject_on_worker_lost`
redeliver after worker death; task re-runs the physical capture then hits an
unhandled `IntegrityError` (`ingest_capture` = plain add+flush on unique
`capture_id`). The `celery_app.py` "pre-created capture row guards re-entry"
comment is false.
- Fix: claim-based CAS / `ON CONFLICT DO NOTHING` keyed on `capture_id`,
  mirroring `config.py::_claim_backup_run`; correct the queue-rationale
  comment in the same commit.
- Test: redelivered task with existing `capture_id` row is a no-op success,
  no duplicate physical capture attempt.

### T7 — H11: fail-closed KEK audit helper triplicated and drifted
`backend/app/services/config_archives.py:256-257` vs
`credentials/service.py` / `credentials/rotation.py:137-172`. Three copies:
one `except Exception: pass` (KEK outage + failed audit write = zero trace),
one unguarded (audit-DB error masks the original `KeyProviderUnavailable`).
- Fix: one shared `_audit_fail_closed()` helper (try/except +
  `kek.provider.unavailable.audit_failed` log-on-failure); reuse from all
  three sites. **Secret-surface → STRONG model, per standing policy.**
- Test: audit-write failure during a fail-closed event logs and does not mask
  the original exception, at all three call sites.

## Group B — Perf quick wins (perf review CRIT/#6)

### T8 — bcrypt off the event loop (perf #6 / repo H2)
`backend/app/core/security.py:138,151`; call sites `auth/login.py:285,289`,
`account.py:173-176`, `users.py:204,323`. 200–300 ms full-loop stall per hash;
10 concurrent logins serialize ALL in-flight requests 2–3 s.
- Fix: `asyncio.to_thread` on hash/verify (login, password change, dummy-hash
  on unknown user). Async signatures propagate to call sites.
- Test: existing auth suites green; add a unit asserting hash/verify execute
  off-loop (e.g. patch `to_thread` / assert loop not blocked).

### T9 — WS trace stream 50 Hz N+1 poll (perf #4 CRIT)
`backend/app/api/v1/agents.py:148,152,632-657`, `_load_traces` `:342-364`.
20 ms poll + per-trace full reload in fresh sessions ≈ 400 q/s per open
socket, redundant with the Redis relay.
- Fix: fallback poll interval ≥500 ms + single "steps newer than cursor"
  query; Redis pub/sub carries liveness (relay already exists at `:651`).
- Test: WS relay tests stay green (post-#90 NullPool conftest — failures are
  real); add assertion on poll cadence/query shape.

### T10 — auto-rebuild perpetual re-projection (perf #3 CRIT)
`backend/app/engines/topology/auto_rebuild.py:80-89`,
`deploy/kubernetes/netops/values.yaml:414,418`. Staleness threshold (300 s) ==
schedule period (5 min) → ~288 full drop-and-reproject cycles/day on an idle
estate; readers race the wiped graph.
- Fix: gate on drift watermark (PG change watermark vs graph `projected_at`),
  or set staleness ≥ 2× schedule; update both values.yaml defaults and code
  default coherently.
- Test: idle estate tick → no rebuild; post-change tick → rebuild. Pairs with
  T3 (same file) — keep commits separate, T3 first.

## Group C — Frontend (repo-review H14/M24/M34)

### T11 — H14: `DiscoveryRunStatus` missing `"partial"`
`frontend/src/api/discovery.ts:13` + `pages/DevicesPage.tsx:50,314`. Backend
enum has five values; FE union four → `RUN_VARIANT[run.status]` undefined,
broken StatusPill on a normal partial run today.
- Fix: add `"partial"` + StatusPill variant. (Codegen/contract test is Wave 4;
  do the point fix now.) Sweep sibling `vi.mock`s if any export changes
  (L-FE-1).
- Test: partial run renders a defined pill variant.

### T12 — M24: ChatPage socket leak on unmount
`frontend/src/pages/ChatPage.tsx:163-165,224`. Socket assigned after `await`
post-unmount never closed (cleanup already ran) → bounded leak +
setState-on-unmounted until stream end.
- Fix: cancelled flag / AbortController in the effect; close socket if effect
  torn down before assignment.
- Test: unmount before socket-open resolves → socket closed, no state update.

### T13 — M34: API client gains `AbortSignal` + timeout
`frontend/src/api/client.ts:108-125`. Zero `AbortSignal`/timeout across the
API layer; TanStack Query cancellation never reaches `fetch`; stalled backend
hangs requests forever.
- Fix: accept/forward `signal` through the client; default
  `AbortSignal.timeout(...)` (combine with caller signal via
  `AbortSignal.any`). Thread `signal` from query hooks where trivially
  available; full hook-layer adoption is Wave 6.
- Test: timed-out request rejects with abort; caller signal cancels in-flight
  fetch.

## Group D — Test/CI hygiene (testing review F2/F6/F9-part)

### T14 — F2: frontend coverage floor
No coverage measurement exists at all.
- Fix: `@vitest/coverage-v8` dev-dep (lockfile same commit) + coverage
  thresholds in vitest config + CI enforcement in the frontend job.
- Bite proof: set threshold above current actual → RED → set to ratchet floor
  (just below current) → GREEN. Run URLs in PR body.

### T15 — F6: pytest-timeout + de-sleep real-clock tests
- Fix: `pytest-timeout` dev-dep (~60 s default, lockfile same commit);
  replace real `asyncio.sleep(5)` in `tests/test_health.py:117` and
  `tests/agents/framework/test_tools.py:121` with event-driven waits.
  Frontend fake-timer migration for polling tests is opportunistic, not
  gating.
- Verify: full suite green; wall time not regressed.

### T16 — F9 (part): CI Node 22 + SHA-pin actions
- Fix: bump CI Node to 22 (match runtime baseline); pin every
  `actions/*@vN` to a full commit SHA with a version comment.
  (Checksum kubeconform/kube-linter + bounded retries stay in Wave 7.)
- Verify: all jobs green post-pin; no tag-drift surface remains in `ci.yml`.

---

## Ordering & dependencies

1. Commit order within the PR is free except: **T3 before T10** (same file,
   gauge fix first so the watermark-gate diff is clean), and **T8 before T9**
   only if auth tests share fixtures touched by both (else parallel).
2. T7 is the only secret-surface task — assign STRONG model explicitly
   (never "inherit").
3. T14/T15 add dev-deps — lockfile regeneration in the same commits.
4. T16 last among CI edits so pins cover any steps the wave itself adds.

## Gates (per task and PR exit)

- Backend: `pytest` (SQLite unit) + `pg-integration` job green;
  `ruff check . && ruff format --check . && mypy && lint-imports`.
- Frontend: `vitest` + typecheck + lint; after T14, coverage floor active.
- New `tests/pg/*.py` (if any) must carry
  `pytestmark = pytest.mark.integration` and prove collection via
  `-m integration --collect-only`.
- Bite proofs for T14 (coverage) documented with run URLs in the PR body;
  PR-body green claims re-verified at final HEAD before merge.
- `graphify update .` after merge.

## Exit criteria

- All 16 tasks landed as atomic commits, one PR, all CI checks green.
- H1/H5/H6/H9/H10/H11/H13/H14, M24/M34 closed with regression tests.
- Perf: auth paths no longer block the loop; per-socket WS DB load reduced
  >99% (poll cadence + cursor query); idle-estate rebuilds eliminated.
- Frontend coverage floor + pytest-timeout active in CI; actions SHA-pinned
  on Node 22.
- `REVIEW-WAVES-PLAN.md` status table updated (Wave 2 → merged, PR #).
