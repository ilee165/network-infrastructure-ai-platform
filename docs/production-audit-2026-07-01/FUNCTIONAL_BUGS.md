# Functional Bugs & Correctness Findings

Production readiness audit, 2026-07-01. Severity: Critical / High / Medium / Low. Effort: S (<0.5 d) / M (0.5–2 d) / L (2–5 d) / XL (>1 wk).

---

## 1. Troubleshooting Agent live-capability reads are permanently dead

- **Severity:** High
- **Location:** `backend/app/agents/troubleshooting/tools.py:161–176` (`_read_live_capability`, consumed by `read_live_bgp_peers` and the other live-read tools)
- **Root cause:** The credential/transport injection seam was deliberately deferred: *"TODO(M5): inject a credentialed transport into impl before this call."* M5 shipped 2026-06-19 and wired credentialed transports for the discovery and config **workers**, but this agent path was never revisited. `get_default_registry().resolve()` returns the capability **class** (`backend/app/plugins/registry.py:58`), no transport is ever constructed, and every live read returns `{"error": "live '<capability>' read for vendor '<vendor>' is not yet wired: the credential/transport session lands in M5"}`. The string "not yet wired" appears nowhere else in the repo and **no test exercises the wired path**, so the regression is invisible to CI.
- **User impact:** The Troubleshooting Agent silently degrades to stored-data-only analysis. Live BGP peer state, live OSPF adjacency, and live route reads — advertised troubleshooting capabilities (CLAUDE.md "Troubleshooting → BGP/OSPF/Routing analysis") — always fail with an error the LLM then has to paraphrase to the user.
- **Proposed fix:** Mirror the worker-side pattern (`backend/app/workers/tasks/discovery.py`): resolve the device's credential via the credential service, build the vendor transport, instantiate the capability implementation with it, and run the read in `asyncio.to_thread` (already done). Add tests for the wired path plus a regression test asserting no tool ever returns the "not yet wired" sentinel. Note this is a credential-touching surface — per repo policy, route the change through strong-model/security review.
- **Effort:** M–L (the seam is clean; test surface is the bulk)
- **Risk of fix:** Medium — touches credential plumbing; read-only capability calls bound the blast radius.

## 2. WebSocket fan-out relay race (recurring CI flake, real fix pending)

- **Severity:** Medium
- **Location:** `backend/app/services/agent_stream/` (Redis pub/sub relay); reproduced by `backend/tests/api/test_agents.py::test_live_frame_published_by_another_replica_is_relayed`
- **Root cause:** Terminal-event ordering race in the cross-replica relay: the test intermittently fails with `KeyError: 'event'` when the terminal event lands relative to subscription/replay in the wrong order. Tracked as a known flake (cleared with `gh run rerun --failed`), which means the underlying race also exists in production streaming: a client attaching to a session served by another replica can, in a narrow window, miss or misorder the terminal frame.
- **Proposed fix:** Make terminal-event delivery deterministic — e.g., sequence-number frames and have the WS handler reconcile pub/sub frames against the durable DB replay (the design already treats DB as durable source), or hold the subscription barrier until replay watermark is established. Then delete the rerun-to-green habit.
- **Effort:** M
- **Risk of fix:** Medium — live streaming path; strong existing test coverage helps.

## 3. Redis client never closed on application shutdown

- **Severity:** Medium
- **Location:** `backend/app/main.py:71` (client creation) vs `backend/app/main.py:149–152` (lifespan shutdown: only `db.dispose_engine()`)
- **Root cause:** The lifespan creates one shared `redis.asyncio` client (rate limiter, stream fan-out, ticket store) but the shutdown path never calls `aclose()` on it. Connections are abandoned to GC.
- **User impact:** Unclean rolling restarts (RST-terminated connections, noisy Redis logs), event-loop warnings in test harnesses and dev reload, and a slow connection-slot leak under orchestrators that restart pods frequently.
- **Proposed fix:** `await redis_client.aclose()` (and any pub/sub subscribers held by the fan-out) after `yield`, before/alongside `db.dispose_engine()`.
- **Effort:** S
- **Risk of fix:** Low.

## 4. Token refresh has no single-flight guard

- **Severity:** Low
- **Location:** `frontend/src/api/client.ts` (`attemptRefresh`, called from `apiFetch`)
- **Root cause:** When a page issues N parallel requests with an expired access token, all N receive 401 and each fires its own `POST /auth/refresh`. Today this is harmless only because the backend deliberately keeps superseded refresh tokens valid within the session (see PRODUCTION_READINESS #5); every parallel refresh succeeds. The moment refresh-reuse detection is added server-side (recommended), these parallel refreshes become session-revoking false positives that log users out.
- **Proposed fix:** Module-level in-flight promise: first 401 starts the refresh, concurrent callers await the same promise. Do this **before or together with** any server-side reuse-detection work.
- **Effort:** S
- **Risk of fix:** Low.

## 5. Index-keyed list rendering

- **Severity:** Low
- **Location:** `frontend/src/pages/ChatPage.tsx:259,261` (conversation turns), `frontend/src/pages/ConfigPage.tsx:225,312` (diff lines)
- **Root cause:** `key={i}` on dynamic lists. Both lists are effectively append-only today, so no user-visible misrender occurs — but any future insertion/reordering (e.g., editing or collapsing chat turns) will cause React to recycle the wrong DOM/state.
- **Proposed fix:** Key chat turns by a stable turn id (the session trace already has one); key diff lines by `${lineNo}-${content hash}` or accept and document the constraint.
- **Effort:** S
- **Risk of fix:** Low.

## 6. Stale placeholder comments in the composition root

- **Severity:** Low
- **Location:** `backend/app/main.py:146–150` ("M1 placeholder hook: initialize the shared async DB engine pool … once domain models land", "M2 placeholder hook: initialize the shared Neo4j driver")
- **Root cause:** Comments predate M1/M2 delivery (models and the Neo4j knowledge layer landed long ago; the engine is initialized lazily elsewhere and disposed here). They now actively mislead a reader auditing startup behavior.
- **Proposed fix:** Delete or rewrite to describe the actual lazy-init contract.
- **Effort:** S
- **Risk of fix:** None.

---

## Verified non-findings (checked, clean)

- **Timezone handling:** zero `datetime.utcnow()` in app code.
- **Broad exception handling:** 17 `except Exception` sites, every one annotated with a fail-open/fail-closed rationale (`# noqa: BLE001 — …`); the KEK path in `main.py` correctly re-raises in prod.
- **Pagination:** all list endpoints carry `limit ≤ 500` + `offset` except `topology /graph` (tracked as ARCHITECTURE_DEBT #7) and the admin user list (bounded by real-world user counts).
- **Celery reliability:** `task_acks_late=True`, `task_reject_on_worker_lost=True`, `worker_prefetch_multiplier=1`, `autoretry_for` on transport errors — matches the ADR-0008/0043 idempotency claims.
- **Blocking calls in async paths:** capability calls run via `asyncio.to_thread` (9 sites) / executors (2); the one `time.sleep` is inside a synchronous Celery task, which is correct.
- **Frontend type hygiene:** zero `: any`, zero `@ts-ignore`, zero `eslint-disable` across 67 files / 14k LOC.
