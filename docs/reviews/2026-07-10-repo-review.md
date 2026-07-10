# Repository Review — 2026-07-10

- **Scope:** full repository (`main` @ `477b51e`, clean tree)
- **Focus:** correctness, readability, maintainability, dead code, duplicated logic, large
  functions, hidden complexity, improper abstractions, error handling, logging, configuration
  management. Formatting excluded.
- **Method:** 8 parallel read-only reviewer agents, one per slice (backend core, API+schemas,
  agents/LangGraph, vendor plugins, engines, services+workers, frontend, deploy/CI). Every source
  file in each slice was read. Every CRITICAL and HIGH finding was then independently re-verified
  against the cited lines by the orchestrating reviewer before inclusion.
- **Legend:** ✓ = independently re-verified at the cited lines; ◦ = reviewer finding backed by an
  exact code quote, not independently re-read.

## Verdict

Codebase discipline is well above average — ADR-driven, fail-closed crypto/audit design, no secret
leakage into logs found anywhere, a clean linear migration chain, and consistent CI pinning. The
dominant defect classes are not sloppy code but:

1. **Built-but-never-wired controls** — documented safety mechanisms no production path invokes.
2. **Copy-paste divergence** across vendor plugins and frontend pages, already behavioral (not
   cosmetic) in at least six places.
3. **Test-blind seams** — every CRITICAL lives where the suite structurally cannot see it
   (Helm render vs real `Settings`, fixture SSH vs real netmiko/Tcl, `MockTransport` vs real httpx
   pool, SQLite vs PostgreSQL partitioning).

Severity counts: **6 CRITICAL / 14 HIGH / 47 MEDIUM / 13 LOW**.

---

## CRITICAL

### C1 ✓ `backend/app/api/deps.py:340` — forced-password-change guard is dead code; every real route bypasses it
- **Category:** error handling / dead code
- **Explanation:** `get_active_user` (deps.py:306, docstring: "Gate the rest of the app with
  this") has zero production call sites — `require_role`'s `_enforce` and all self-service routes
  resolve through bare `get_current_user`. A `must_change_password` user can call any
  engineer/admin endpoint via direct API access; only the SPA redirect enforces the flag. The only
  test mounts a synthetic probe route, so it proves nothing about real routes.
- **Fix:** Route `_enforce` through `get_active_user` (keeping the documented `/me`,
  `/me/password`, `/logout` exceptions) and add a test that hits a real protected route with a
  flagged user.

### C2 ✓ `backend/app/plugins/vendors/junos/plugin.py:383-403` + `backend/app/plugins/transport/ssh.py:190-259` — JunOS `commit confirmed` documented but never issued; JunOS config writes are no-ops
- **Category:** correctness / hidden complexity
- **Explanation:** Plugin docstrings (and ADR-0026's justification for skipping the
  management-path guardrail) promise `load merge` → `commit confirmed <N>` → confirming `commit`,
  "driven by the transport's `send_config`". The shared `SshTransport.send_config` only calls
  netmiko `send_config_set` — no commit exists anywhere in the file — and `replace_config` sends
  Cisco-only syntax (`flash:`, `tclsh`, `configure replace`) that does not exist on JunOS. Every
  JunOS deploy/restore/rollback never commits; the dead-man auto-revert cited as the safety
  control does not exist.
- **Fix:** Dedicated JunOS `ConfigWriteTransport` issuing `load merge`/`load override` +
  `commit(confirm=True)` + confirming commit, with `rollback N` as the inverse.

### C3 ✓ `backend/app/plugins/transport/ssh.py:241` — unescaped config text interpolated into a Tcl string corrupts `replace_config` staging
- **Category:** correctness
- **Explanation:** `f'puts [open "{staged}" w+] "{candidate}"'` embeds the entire multi-line
  candidate config inside a Tcl double-quoted string. Literal `$`, `"`, `[`, `]` (common in
  banners, AS-path regexes, cert blobs) trigger Tcl substitution or terminate the string,
  corrupting the staged file; device errors return as plain output text, not exceptions. This is
  the sole apply surface for `CONFIG_RESTORE` and the sole rollback surface for
  cisco_ios/iosxe/nxos/eos. The post-apply equality assert likely converts silent corruption into
  a *failed rollback* — still the safety net failing during an incident.
- **Fix:** Escape Tcl metacharacters or base64-encode the payload and decode device-side; fail
  closed on tclsh error output.

### C4 ✓ `backend/app/agents/automation/agent.py:289` — approved CR permanently stranded in `executing` on any finalize-time exception
- **Category:** error handling / state machine
- **Explanation:** `mark_executing` (line 280) claims the CR (`approved → executing`), then
  `_apply_and_finalize` runs unwrapped — any unexpected executor raise, or a transient DB error
  during the finalize write itself, escapes `execute()`, leaving the CR in `executing`.
  `execute()` refuses non-`approved` CRs, so re-attempts are refused forever, and no
  stale-executing reaper exists in `change_requests/service.py`. Manual DB surgery is the only
  recovery, on the platform's most security-critical write path.
- **Fix:** Wrap `_apply_and_finalize` in try/except inside `execute()`; on unexpected exception
  mark the CR `failed` with an audit row, mirroring the existing `_fail_no_executor` fail-closed
  pattern.

### C5 ✓ `deploy/kubernetes/netops/templates/_helpers.tpl:74` + `backend/app/main.py:71` — enabling the Redis Sentinel HA tier crashes the API pod at boot
- **Category:** configuration management / correctness
- **Explanation:** With `redisSentinel.enabled=true`, `NETOPS_REDIS_URL` renders
  `sentinel://h0:26379;h1:26379;h2:26379/0`. `redis.asyncio.from_url` accepts only
  `redis`/`rediss`/`unix` schemes and raises `ValueError` at parse time; `main.py:71` calls it
  unguarded in `lifespan` (the "client is lazy" comment covers unreachable Redis, not unparseable
  URLs). Same call in `api/v1/health.py:101`. Kombu (the worker broker) does parse `sentinel://`,
  which is why the helper's docstring assumed both clients would. Only the non-blocking,
  signal-only kind-HA CI job could have caught this.
- **Fix:** Construct a `redis.asyncio.sentinel.Sentinel` client when the scheme is `sentinel://`,
  or render a redis-py-compatible URL and pass sentinel coordinates via dedicated env vars.

### C6 ✓ `deploy/kubernetes/netops/templates/configmap.yaml:52-54` — Helm LLM/Ollama configuration is entirely dead; default host never matches the chart's Service
- **Category:** configuration management
- **Explanation:** `NETOPS_LLM_PROVIDER` / `NETOPS_OLLAMA_HOST` / `NETOPS_OLLAMA_PORT` match no
  `Settings` field (real fields: `NETOPS_LLM_PROFILE`, `NETOPS_OLLAMA_BASE_URL`; `Settings` has
  `extra="ignore"`, so the keys are silently dropped). `values.yaml`'s `provider: ollama` is not
  even a valid profile (`KNOWN_PROFILES = ("local", "anthropic", "openai", "azure")`). The app
  falls back to `http://ollama:11434` while the chart's Service is `netops-ollama` — DNS miss.
  Local-first LLM on the Helm path is non-functional out of the box, and the knobs fail silently.
- **Fix:** Emit `NETOPS_LLM_PROFILE` + `NETOPS_OLLAMA_BASE_URL` built from the values; default
  `provider` to `local`.

---

## HIGH

### H1 ✓ `backend/app/api/v1/devices.py:168,199` — mgmt_ip unique-race returns 500 instead of 409
- **Category:** correctness / error handling
- **Explanation:** Create/update flushes have no `IntegrityError` guard (delete at :225 does);
  concurrent same-`mgmt_ip` writes pass `_ensure_mgmt_ip_free` then fail as an unhandled 500.
  `applications.py:315,377,510` already fixed exactly this race, citing devices.py as its
  precedent; never backported. A 2026-06-11 review note flagged this race and it was never closed.
- **Fix:** Wrap both flushes; `IntegrityError` → `ConflictError`, mirroring `applications.py`.

### H2 ✓ `backend/app/core/security.py:138,151` — bcrypt runs on the event loop
- **Category:** async misuse
- **Explanation:** `checkpw`/`hashpw` (~100-300 ms CPU) are called directly from async auth routes
  (`login.py:285,289`, `account.py`, `users.py`); every login stalls all concurrent requests on
  that worker, and the timing-equalizer means it fires on 100% of login traffic. The codebase
  offloads comparable calls elsewhere (`main.py:118` uses `asyncio.to_thread`).
- **Fix:** Async wrappers in `core/security.py` using `asyncio.to_thread` so every caller gets the
  offload by construction.

### H3 ✓ `backend/app/core/config.py` vs `.env.example` — 19 documented vars vs ~82 Settings fields; header claims 1:1
- **Category:** configuration management
- **Explanation:** Entire security-relevant areas (KMS/KEK backends, OIDC, rate-limit/lockout,
  SIEM export, DB mTLS, retention windows) have zero `.env.example` presence, violating the
  project's own stated 1:1 contract (CLAUDE.md; sole documented exception
  `NETOPS_ADMIN_PASSWORD`). An operator following `.env.example` cannot discover dozens of
  hardening knobs.
- **Fix:** Generate `.env.example` from the `Settings` field list with a CI check, or explicitly
  partition quickstart vs advanced and update the header + CLAUDE.md claim.

### H4 ✓ `backend/alembic/versions/0001_m1_baseline.py:50-53` (also `0004:46-49`, `0011:109`) — monthly partitions end at `2026_07`; no creation job exists
- **Category:** hidden complexity / configuration management
- **Explanation:** `audit_log`, `raw_artifacts`, `reasoning_traces`, `reasoning_trace_steps` are
  range-partitioned with explicit partitions only through 2026-07 plus a DEFAULT partition. Zero
  partition-creation code exists anywhere in `backend/app`. From 2026-08-01 (~3 weeks after this
  review) every row lands in the unbounded DEFAULT partition — partition pruning and
  partition-drop retention permanently defeated for that data.
- **Fix:** Celery-beat task (like the existing retention jobs) pre-creating next month's
  partitions for all four tables, or a documented migration cadence.

### H5 ✓ `backend/app/engines/security/firewall.py:302-304` — management-plane exposure check misses `services=("any",)`
- **Category:** correctness
- **Explanation:** `named_services & MANAGEMENT_SERVICES` is an exact-name intersection; a
  wildcard service rule (which trivially includes SSH/RDP/Telnet) from `source=any` never fires
  the HIGH management-plane finding, only a generic MEDIUM. A false negative in a tool whose
  purpose is trusted signal.
- **Fix:** When the services/applications dimension is `any`, treat `exposed` as the full
  `MANAGEMENT_SERVICES` set.

### H6 ✓ `backend/app/engines/topology/auto_rebuild.py:165-167` — steady-state ticks force the edge gauge to 0
- **Category:** correctness
- **Explanation:** The no-op reconcile path hard-codes `edges = 0` into `observe_rebuild` and the
  metrics textfile because `graph_freshness` only queries node count. The
  `topology_rebuild_edges` series consumed by the DR/RTO drill and G-OBS SLO reads 0 in the
  healthy common case — masking a real edge-count collapse and normalizing the noise value.
- **Fix:** Query the live edge count on the no-op path, or leave the last real gauge value in
  place.

### H7 ✓ `backend/app/plugins/transport/ssh.py:136-144` — SSH host keys never verified
- **Category:** configuration management / error handling
- **Explanation:** `ConnectHandler` is called without `ssh_strict`/`system_host_keys`; netmiko's
  default selects paramiko `AutoAddPolicy`, so every CLI vendor silently accepts any host key —
  MITM/host-substitution exposure contradicting the "secure by default" principle.
- **Fix:** Default `ssh_strict=True` + `system_host_keys=True`, or a pinned per-device host-key
  fingerprint on `ConnectionParams`, with an explicit lab-only opt-out.

### H8 ◦ `cisco_ios/plugin.py:475-588`, `cisco_iosxe/plugin.py:368-466`, `cisco_nxos/plugin.py:470-553`, `eos/plugin.py:436-536`, `junos/plugin.py:443-546` — ADR-0021 write engine copy-pasted 5×
- **Category:** duplicated logic / maintainability
- **Explanation:** ~150-200 lines of apply→verify→rollback state machine (`_execute`,
  `_rollback_to_baseline`, `_diff_summary`, `_normalize_config`, `_require_executing`, capture
  helpers) re-implemented per vendor. This is exactly why C2/C3 hide behind five sets of green
  fixture tests — an engine fix must be applied five times.
- **Fix:** Extract the shared engine into `plugins/base.py` (or a new module) parameterized by
  vendor normalize/guardrail hooks.

### H9 ✓ `backend/app/plugins/vendors/spatiumddi/plugin.py:200` + `client.py:104` — one `httpx.AsyncClient` reused across per-call `asyncio.run()` loops
- **Category:** correctness / hidden complexity
- **Explanation:** Each capability call runs on a fresh event loop (`asyncio.run`), but the single
  `AsyncClient` built in `__init__` binds its httpcore pool lock to the first loop; the second
  read method on a device session raises `RuntimeError` in production. Invisible in tests because
  `MockTransport` has no connection pool. Crashes SpatiumDDI discovery (loud, vendor-scoped).
- **Fix:** One event loop per device session, or a fresh client per `_run` invocation.

### H10 ✓ `backend/app/workers/tasks/packet.py:382` (+ `engines/packet/capture.py:279`, `celery_app.py:102-107`) — capture tasks not idempotent under redelivery; queue-rationale comment is false
- **Category:** correctness
- **Explanation:** Global `task_acks_late` + `task_reject_on_worker_lost` redeliver after worker
  death; the task re-runs the physical capture (for `capture_device`, re-driving CLI on a live
  device) then hits an unhandled `IntegrityError` because `_persist_capture` sits outside the
  try/except and `ingest_capture` is a plain add+flush against a unique `capture_id`.
  `celery_app.py` claims "a pre-created capture row whose state machine guards re-entry" — no such
  row exists. (The unique constraint prevents data corruption; damage = duplicate physical capture
  + task failure, hence HIGH not CRITICAL.)
- **Fix:** `ON CONFLICT DO NOTHING`/CAS keyed on `capture_id`, mirroring `config.py`'s
  `_claim_backup_run`; correct the queue-rationale comment.

### H11 ✓ `backend/app/services/config_archives.py:256-257` vs `credentials/service.py` / `credentials/rotation.py:137-172` — "durably audit a fail-closed KEK event" helper triplicated and drifted
- **Category:** error handling / duplicated logic / logging
- **Explanation:** Three near-identical implementations. `config_archives`' copy is
  `except Exception: pass` — a KEK outage whose audit write also fails leaves zero trace (the
  credentials version logs `kek.provider.unavailable.audit_failed`). `rotation.py`'s copy has no
  guard at all, so an audit-DB error while recording `KEK_ROTATE_INTERRUPTED` masks the original
  `KeyProviderUnavailable` mid-incident.
- **Fix:** One shared `_audit_fail_closed()` helper with the try/except + log-on-failure behavior;
  reuse from all three sites.

### H12 ✓ `backend/app/workers/tasks/discovery.py:571` + `config.py:513-521` — parent task blocks on `.get(disable_sync_subtasks=False)` for children routed to the same queue
- **Category:** async misuse / hidden complexity
- **Explanation:** `discovery.*` → `QUEUE_DISCOVERY` routes parent and children to the same worker
  pool; the parent holds a slot for the whole run while children wait behind it. Worker
  `--concurrency` is unpinned in Helm, so a common low-concurrency tuning starves or deadlocks the
  wave — the exact anti-pattern Celery's (explicitly disabled) guard exists to prevent.
- **Fix:** Separate child queue or chord/callback fan-out; document and enforce a minimum worker
  concurrency for self-fanning queues.

### H13 ✓ `backend/app/agents/framework/tools.py:538` vs `:383` — exception `detail` bypasses the A9 redaction chokepoint
- **Category:** error handling / logging
- **Explanation:** `_emit` (self-described "single audit-emit chokepoint") redacts `arguments` via
  `redact_payload` but persists `detail=str(exc)` raw. Pydantic `ValidationError.__str__()` embeds
  offending input values, so a secret echoed into a mistyped tool argument lands unredacted in the
  durable audit log. No global log scrubber exists in `core/logging.py`.
- **Fix:** Route `detail` through `redact_prompt`/`redact_payload`, or sanitize exception text the
  way `security/tools.py::_sanitized_validation_error` does.

### H14 ✓ `frontend/src/api/discovery.ts:13` + `pages/DevicesPage.tsx:50,314` — `DiscoveryRunStatus` missing backend `"partial"`
- **Category:** correctness (API type drift)
- **Explanation:** Backend enum has five values (`models/inventory.py:76-83`); the hand-written
  frontend union has four. `RUN_VARIANT[run.status]` is `undefined` for a normal partial run —
  broken StatusPill on the Devices page today. Concrete proof of the no-codegen drift risk.
- **Fix:** Add `"partial"` + variant now; longer-term generate the unions from the backend OpenAPI
  schema, with a contract test.

---

## MEDIUM

### Backend API
- **M1 ◦ `api/v1/agents.py:342-364,632-657`** — WS poll loop reloads *all* traces every tick
  (1 + 2N queries via `PostgresTraceRecorder.get` per trace); loop sized for up to 1500
  iterations. *Fix:* incremental load of only new steps.
- **M2 ◦ `api/v1/agents.py:1150`** — sync `tshark` subprocess reachable on the event loop when
  sandbox enforcement is off (non-default config). *Fix:* `asyncio.to_thread` on that path.
- **M3 ◦ pagination boilerplate ×13** — identical `items/total/limit/offset` schema + count/
  paginate route pattern (schemas: `devices.py:103`, `changes_api.py:56`, `config_mgmt.py:66,170`,
  `credentials.py:91`, `applications.py:93`, `discovery_api.py:91`, `adc.py:48,87`,
  `virtualization.py:84,125,150,183`; routes: `agents.py:885`, `adc.py:55,101`,
  `applications.py:233`, `config_snapshots.py:97`, `credentials.py:147`, `devices.py:94`,
  `docs.py:60`, `discovery.py:109`, `virtualization.py:69,118,164,210`). *Fix:* generic `Page[T]`
  + shared `paginate()`.
- **M4 ◦ audit-actor construction ×~23** — `f"user:{user.username}"` inlined ~20× plus three
  identical private `_actor` helpers (`credentials.py:52`, `devices.py:53`, `applications.py:92`).
  *Fix:* one shared helper.
- **M5 ◦ `api/v1/auth/users.py:163-170`** — the one unpaginated collection endpoint (every
  sibling caps at 500). *Fix:* same limit/offset treatment.
- **M6 ◦ `api/v1/agents.py:453-541,567-675`** — `start_session` (~89 lines) and `stream_session`
  (~109 lines) fuse 5+ concerns each; the first-token metric block is only testable end-to-end.
  *Fix:* extract audit/metric helpers.

### Backend core
- **M7 ✓ `db.py:206-221`** — `get_read_session` (the whole ADR-0042 replica-read stack) has zero
  production callers; its docstring claims present-tense read offload. *Fix:* wire the intended
  read-only routes or mark the dependency unwired/planned.
- **M8 ◦ `llm/providers.py:50` / `core/config.py:427-430` / `llm/runtime_settings.py:36-39`** —
  the LLM role set is hand-duplicated in three files; adding a role passes the typed guard then
  raises a bare `KeyError`. *Fix:* derive all three from one constant, or a load-time assertion.
- **M9 ◦ `main.py:48-153`** — ~105-line lifespan mixing Redis wiring, KMS provider gate, startup
  audit, and shutdown. *Fix:* named async helpers per concern.

### Engines
- **M10 ◦ `engines/topology/app_derivation.py:289-681`** — one ~390-line function fusing three
  derivation algorithms (F5, VMware, DNS) with shared mutable locals. *Fix:* three source-specific
  pure functions + slim orchestrator.
- **M11 ◦ `app_derivation.py:459-470`** — exact-hostname collision silently returns the first
  match while the short-name fallback two lines later refuses ambiguity (`len == 1` guard).
  *Fix:* apply the same guard + record in `DerivationStats`.
- **M12 ◦ `app_derivation.py:500-521`** — O(VMs × F5-pool-members) nested scan. *Fix:* pre-index
  evidence by address and fqdn key.
- **M13 ◦ `engines/topology/projector.py:427-477`** — wipe/project issued as many auto-commit
  statements with no enclosing transaction; a mid-pass crash leaves a partially empty graph until
  the next reconcile tick. *Fix:* explicit transaction, or document reliance on `auto_rebuild` as
  the compensating control.
- **M14 ✓ IP-canonicalization ×3** — `app_derivation.py:194`, `dns.py:161`, `expansion.py:21`;
  expansion's copy omits `.strip()` (real dedupe divergence; its non-IP pass-through is deliberate
  for hostname targets). *Fix:* one shared `canonical_ip` helper.
- **M15 ◦ `engines/packet/executor.py:306-312,392-394`** — a seccomp DENY-rule/add failure
  escapes the documented `ConfinementError`/exit-code taxonomy (raw traceback, generic exit 1).
  *Fix:* wrap the whole `_install_seccomp_filter` body in the ConfinementError mapping.

### Services / workers
- **M16 ◦ `services/change_requests/service.py:251-289`** — `update_draft` mutates
  payload/rollback-plan with no audit row; every sibling mutator writes one. *Fix:* add a
  `change_request.draft_updated` audit (never the secret-bearing payload).
- **M17 ◦ `services/credentials/service.py:578-653`** — `rotate_kek` (76 lines, whole-corpus
  single transaction) has zero production callers; superseded by `re_wrap_keys`. *Fix:* delete or
  wire a documented entrypoint.
- **M18 ◦ `workers/tasks/discovery.py:696-703`** — unbounded single-statement retention DELETE on
  `raw_artifacts`; sibling bulk paths deliberately batch. *Fix:* batched delete loop.
- **M19 ◦ `workers/tasks/{discovery,config,packet,topology}.py`** — `_make_engine`/`_session`
  scaffolding copy-pasted 4×. *Fix:* shared `task_session()` async contextmanager.

### Plugins
- **M20 ◦ `plugins/vendors/cisco_nxos/parsers.py:153-155`** — blank output treated as "feature
  disabled": collection failures masked as legitimately-empty results; sibling vendors raise.
  *Fix:* only the explicit sentinel text means disabled; blank raises.
- **M21 ◦ `cisco_nxos/parsers.py:492` vs `cisco_ios/parsers.py:140-152,465`** — NX-OS `int()` on
  asdot AS numbers fails the entire BGP capture where IOS parses fine (`_parse_as_number`).
  *Fix:* share the AS-number parser.
- **M22 ◦ infoblox/bluecat/spatiumddi clients** — secret-redaction logging filter present in
  panos/fortios/f5/vmware, absent in these three despite a docstring parity claim. *Fix:* add the
  filters or correct the claim.
- **M23 ◦ `f5_bigip/client.py:396-412`** — a non-`httpx.HTTPError` during token revoke skips
  `_client.close()` and the logger filter removal. *Fix:* `finally` block.

### Frontend
- **M24 ✓ `pages/ChatPage.tsx:163-165,224`** — socket assigned after `await` post-unmount is
  never closed (the unmount cleanup already ran); bounded leak + setState-on-unmounted until the
  stream ends. *Fix:* cancelled flag / AbortController in the effect.
- **M25 ✓ `api/agents.ts:20`** — `AgentSessionStatus` uses `"succeeded"`; the wire value is
  `"completed"` (`models/agents.py:49-54`). Dormant today; same drift class as H14. *Fix:* correct
  the union + contract test.
- **M26 ◦ `pages/UsersPage.tsx:108-112`** — clipboard write of a one-time temp password has no
  `.catch`; denied clipboard = silent nothing. *Fix:* visible copy-failed state.
- **M27 ◦ `ApplicationsPage.tsx:110-159` vs `UsersPage.tsx:60-96`** — `ConfirmDialog` duplicated
  verbatim and already drifted (`data-testid` lost); six hand-rolled modal shells total
  (`ApplicationsPage.tsx:125,233`, `SettingsPage.tsx:823`, `UsersPage.tsx:63,116,196`). *Fix:* one
  shared Modal/ConfirmDialog primitive.
- **M28 ◦ `errorMessage()` ×4** — `SettingsPage.tsx:71-78`, `ProfilePage.tsx:35-42`,
  `UsersPage.tsx:41-48`, `ApplicationsPage.tsx:49-61`; each narrower than `ErrorBanner`'s
  unexported `messageFor` (drops `Error.message`). *Fix:* export and reuse.
- **M29 ◦ `ChangePasswordPage.tsx:36,62-69` vs `ProfilePage.tsx:34,146-153`** — full
  change-password validation + flow duplicated; policy changes will desync. *Fix:*
  `useChangePassword()` hook.
- **M30 ◦ `ConfigPage.tsx:32` + `DocumentsPage.tsx:29`** — `PILL_BASE` badge markup re-rolled
  outside `StatusPill` (already drifted: missing `gap-1`), the primitive whose docstring says it
  exists to end exactly this. *Fix:* migrate the five badges onto StatusPill.
- **M31 ◦ hand-rolled error alerts ×8** — diverge from `ErrorBanner` (`ConfigPage.tsx:132,247,408`,
  `DocumentsPage.tsx:341`, `AuditPage.tsx:66`, `IncidentReportsPage.tsx:150`,
  `TopologyPage.tsx:687,741`). *Fix:* `<ErrorBanner/>` everywhere.
- **M32 ◦ table shell ×31 across 15 files** — `panel overflow-x-auto > table` with per-page
  header/skeleton/empty/pagination wiring (worst: `VirtualizationPage.tsx` ×8, `DevicesPage.tsx`
  ×6, `AdcPage.tsx` ×5; full list in review transcript). *Fix:* shared `DataTable` component.
- **M33 ◦ `VirtualizationPage.tsx:54`** — page-local `EmptyState` shadows the shared component
  (different props); the shared one is imported exactly once while 17 sites hand-roll the block.
  *Fix:* rename the local, extend the shared to cover the common case.
- **M34 ◦ `api/client.ts:108-125`** — zero `AbortSignal`/timeout across the entire API layer;
  TanStack Query's cancellation never reaches `fetch`; a stalled backend hangs requests forever.
  *Fix:* accept/forward `signal`, add an `AbortSignal.timeout` default.
- **M35 ◦ `pages/SettingsPage.tsx` (1598 lines)** — eight route-mounted concerns in one file
  (`SettingsCredentialsSection` alone ~478 lines). *Fix:* split into `pages/settings/*.tsx` with a
  thin shell.
- **M36 ◦ `App.tsx:31-58` + `TopologyPage.tsx:22`** — zero route-level code splitting; cytoscape
  ships in the initial bundle to `/login`. *Fix:* `React.lazy` per route + Suspense.
- **M37 ◦ `PacketPage.tsx:35-40` (+`TopologyPage.tsx:351`, `AuditPage.tsx`)** — hand-rolled
  pending/error/result state trio where half the app uses `useMutation`. *Fix:* standardize on
  `useMutation` for writes.

### Agents layer
- **M38 ◦ nine specialist `__init__.py` files** — singleton + registry blocks (import-time agent
  construction) verified dead: `build_default_registry` builds fresh instances; only per-package
  self-tests reference the singletons. *Fix:* reuse them in the composition root or delete the
  pattern.
- **M39 ◦ `troubleshooting/agent.py:252-262` = `configuration/agent.py:227-231`** —
  `_resolve_tool` duplicated verbatim. *Fix:* `BaseSpecialistAgent._tool_by_name`.
- **M40 ◦ `documentation/tools.py:721-728` = `:1019-1026`** — redact → loop sections → `ainvoke`
  → assemble sequence duplicated between runbook and incident report. *Fix:* one shared helper
  parameterized by system prompt + section list.
- **M41 ◦ same lines** — those sequential `model.ainvoke` calls have no timeout (READ_ONLY tools
  get no framework bound, unlike DIAGNOSTIC); a stalled local LLM hangs the calling worker
  indefinitely. *Fix:* `asyncio.timeout` or `bounded_execution` on these tools.

### Deploy / CI
- **M42 ◦ `configmap.yaml:16,57,62`** — `NETOPS_LOG_LEVEL` (nothing reads a log-level env),
  `NETOPS_OIDC_ENABLED` (computed property, not settable), `NETOPS_KMS_PROVIDER` (wrong knob; the
  real selector is `NETOPS_VAULT_KEY_PROVIDER` from a different values path) — all silently
  ignored. *Fix:* remove or wire each.
- **M43 ◦ `ci/{cnpg,mtls,redis-sentinel}/render-twice.sh`** — ~10-line harness preamble
  byte-identical ×3. *Fix:* sourced `ci/lib/render-twice-common.sh`.
- **M44 ◦ `deploy/docker/README.md:11,231`** — still documents the shared worker draining the
  `packet` queue; compose dropped it post-ADR-0049 (`docker-compose.yml:91`). *Fix:* update both
  passages, mention `packet_analysis` service.
- **M45 ◦ `deploy/docker/docker-compose.neo4j-rebuild-drill.yml:42`** — hardcoded
  `ghcr.io/netops/netops-backend:p1` with no `build:`/`pull_policy: build`, reproducing the exact
  "pull access denied" failure the base compose header warns about. *Fix:* local-build pattern or
  documented prerequisite.
- **M46 ✓ `.github/workflows/ci.yml:155,2185`** — CI builds/tests the frontend on Node 20; the
  shipped image is `node:22-alpine` (`frontend.Dockerfile:16`), so the production Node major is
  never exercised in CI. *Fix:* pin CI to 22 (or read from `.nvmrc`/`engines`).
- **M47 ✓ `values.yaml:72` vs `:1055,1152,1216`** — backend image reference in four independent
  places with two conventions (bare vs `ghcr.io/...`); a missed override breaks the
  (often-suspended) backup/DR CronJobs silently until a drill actually runs. *Fix:* derive
  drill/backup images from `.Values.images.backend` by default.

---

## LOW

- **L1 ✓ `api/v1/agents.py:820-822`** — `(Role.from_name(...) or Role.VIEWER).rank <
  Role.VIEWER.rank` is always false (dead), and its `or Role.VIEWER` default is fail-open next to
  `require_role`'s fail-closed `-1`. *Fix:* delete or align fail-closed.
- **L2 ◦ `panos/plugin.py:265-269`** — IP-enrichment `except PluginError` conflates auth failure
  with missing-fixture; no diagnostic trail. *Fix:* log/record the failure reason.
- **L3 ◦ `core/crypto.py:426-428`** — repr comment "never a key handle/ARN" is false for
  `AwsKmsKeyProvider` (`_version = key_arn`). *Fix:* correct the comment.
- **L4 ◦ `engines/discovery/planner.py:79-94`** — frozen model re-parses the CIDR allowlist on
  every `is_allowed` call. *Fix:* `functools.cached_property`.
- **L5 ◦ `engines/packet/executor.py:492` + `sandbox.py:196`** — tshark spawn catches only
  `FileNotFoundError`; `PermissionError` escapes the clean `SandboxError` mapping. *Fix:*
  `except OSError`.
- **L6 ◦ `services/audit/export/formatters.py:139`** — CEF `deviceCustomDate1Label` emitted with
  no matching `deviceCustomDate1` value. *Fix:* drop the orphan or emit the value.
- **L7 ◦ `pages/UsersPage.tsx:433-438`** — both if/else branches call `setPending(null)`; the
  comment describes behavior that does not exist. *Fix:* collapse + drop the stale comment.
- **L8 ◦ `components/FormField.tsx`** — used in 3 of 13+ forms; the a11y gap it was built to fix
  persists elsewhere (`ProfilePage`, `UsersPage` CreateUserModal, `ApplicationsPage` forms,
  launcher inputs). *Fix:* migrate opportunistically.
- **L9 ◦ `documentation/tools.py:37,48`** — sole stdlib-`logging` file in the agents slice; loses
  the structured-kwargs convention. *Fix:* `app.core.logging.get_logger`.
- **L10 ◦ `consultant/agent.py:112`** — `record_question` has no production caller (documented
  "autonomous path", unwired). *Fix:* wire a caller or mark reserved-for-future in the docstring.
- **L11 ◦ `ci.yml:1732-1735`** — kms-emulators job missing the pip cache its sibling jobs use.
  *Fix:* add `cache: pip` + dependency path.
- **L12 ✓ `engines/config_mgmt/drift.py:248`** — `detect_drift` commits internally; deliberate and
  documented (ADR-0017 §2: "The engine owns and commits its audit row"), but composing it into a
  larger unit of work prematurely commits the caller's pending writes and the docstring does not
  warn about that. *Fix:* one docstring sentence.
- **L13 ◦ `troubleshooting/agent.py:236-400`** — 165-line `build_graph` with all node bodies
  inline; sibling `configuration/agent.py` factors its steps out. *Fix:* extract node methods.

---

## Systemic themes

1. **Built-but-never-wired safety controls** — C1 (password gate), C2 (JunOS commit), M7 (replica
   reads), M17 (`rotate_kek`), M38 (nine singletons), L10. Docstrings describe enforcement that
   grep disproves. Recommend a standing rule: every control names its production call site, plus a
   wiring test per control.
2. **Copy-paste divergence** — 5× vendor write engine (H8), NX-OS parser drift (M20/M21),
   redaction-filter parity (M22), KEK-audit helper drifting into `pass` (H11), and the frontend
   table/badge/modal/error family (M27-M33). Behavioral drift already exists in at least six
   places.
3. **Test-blind seams** — every CRITICAL lives where the suite structurally cannot see it: Helm
   render vs real `Settings` (C5/C6), fixture SSH vs real netmiko/Tcl (C2/C3), `MockTransport` vs
   real httpx pool (H9), SQLite vs PostgreSQL partitions (H4). Highest-leverage fixes: a
   config-contract CI check (rendered ConfigMap keys ⊆ `Settings` env names; `.env.example` ⊇
   Settings) and frontend↔backend enum contract tests (H14/M25).
4. **Config contract drift as a class** — H3, C6, M42, M46, M47: the same tunable defined in N
   places, or documented ≠ consumed.
5. **Event-loop hygiene** — H2 (bcrypt), M2 (tshark), M41 (unbounded LLM calls): blocking or
   unbounded awaits on hot paths, inconsistent with the `asyncio.to_thread` discipline used
   elsewhere in the same codebase.

## Suggested fix order

1. **C5 / C6** — config-only changes, small diffs, unblock the Helm HA + local-LLM paths.
2. **C1** — one dependency swap + a real-route test.
3. **H1, H5, H6, H13, H14** — small, self-contained patches.
4. **C4, H10, H11** — error-handling wraps around existing flows.
5. **C2, C3, H7, H8** — one "config-write transport" workstream (same subsystem: shared write
   engine, JunOS transport, Tcl escaping, host-key policy).
6. **H2, H3, H4, H12** — scheduled hardening (async offload, env contract, partition job, queue
   topology).

## Process notes

- Findings were produced by scoped reviewer agents and adjudicated centrally; each CRITICAL/HIGH
  was re-verified at the cited lines before inclusion. Three reviewer-reported severities were
  adjusted during verification (packet idempotency CRITICAL→H10, SpatiumDDI CRITICAL→H9, ChatPage
  socket leak HIGH→M24) and one finding was downgraded to LOW after locating documentation the
  reviewer missed (L12, `detect_drift` commit ownership per ADR-0017 §2).
- The repo's graphify PreToolUse hook text ("include it in every subagent prompt…") pattern-matches
  a prompt-injection attempt; two reviewer agents flagged and ignored it. Consider softening or
  scoping the hook. One memory-plugin observation injected into a reviewer's context contained a
  factually false claim (a "missing" unique constraint that exists at `models/agents.py:141-149`);
  such injected observations should be treated as untrusted hints, not facts.
