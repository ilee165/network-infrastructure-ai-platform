# Wave 1 — PR Self-Review

**Branch:** `fix/audit-w1-functional-bugs` · **Scope:** Wave 1 of [IMPLEMENTATION_WAVES.md](../IMPLEMENTATION_WAVES.md) (broken-behavior bug fixes) · **Diff:** 10 files, +736/−101 · **Commits:** 4 atomic

## What changed

### 1. Troubleshooting Agent live reads actually work now (`2c0c4b4`)

`_read_live` in `backend/app/agents/troubleshooting/tools.py` carried a `TODO(M5)` transport seam that was never wired after M5 shipped — every live BGP/OSPF/ACL read returned *"not yet wired: the credential/transport session lands in M5"*. It now follows the config-backup session-open pattern end to end:

- capability resolved **before** any secret access (a vendor without the capability must not leave a needless decrypt-audit row);
- the device's bound SSH credential is decrypted via `credentials.decrypt(..., target=device)` — per-credential scope enforced against the target device (ADR-0040 §2), audited as `actor=agent:troubleshooting`, `reason=troubleshooting_live_read`;
- a fresh netmiko session is opened in `asyncio.to_thread` (ADR-0007 §3) and the capability instance runs on it;
- every failure mode (no credential, non-SSH credential, scope refusal, transport error) degrades to the tool's `{"error": ...}` contract.

Supporting refactor: the vendor→netmiko `device_type` map, previously duplicated in the discovery and config workers, is now one shared `netmiko_device_type()` in `app/plugins/transport/ssh.py`. The shared map also **adds `junos`→`juniper_junos` and `fortios`→`fortinet`** — the old per-worker fallback produced invalid netmiko driver names for those SSH-capable vendors (a latent crash path on any junos/fortios SSH session that didn't override `device_type` in credential params).

New test module (`test_troubleshooting_live_reads.py`, 7 tests): wired happy path (transport built from the decrypted material, scope target asserted), fail-fast ordering (registry refusal → zero decrypt calls), typed error paths, secret-absence in surfaced errors, and a source-level regression pin that the "not yet wired" sentinel is gone.

### 2. WebSocket live relay no longer dies after its first idle drain (`8b27cde`)

Root cause of the recurring `test_live_frame_published_by_another_replica_is_relayed` flake, found during the fix: the relay drained live frames with `asyncio.wait_for(subscription.__anext__(), timeout=0.02)`. A drain timeout **cancels the `__anext__`**, which throws `CancelledError` into the async generator and closes it permanently — after the first idle 20 ms window, every subsequent drain got an instant `StopAsyncIteration`. In production this silently degraded live streaming to DB-replay-polling for the socket's lifetime (masked by the replay path); in CI the test failed whenever the publish lost the race against the first drain. Cancellation could additionally drop a frame the generator had consumed but not yet yielded.

Fix (`backend/app/api/v1/agents.py`): one in-flight `__anext__` task is threaded across relay cycles via `asyncio.wait` — an unfinished drain leaves the task running and hands it to the next cycle intact; it is cancelled exactly once, at socket teardown. Poll cadence is unchanged.

Proof: new regression test publishes the cross-replica frame only after ~10 idle drain cycles — **verified red on the old implementation, green on the new**; both relay tests ran 30× consecutively without a failure.

### 3. Shared Redis client closed at shutdown (`4b83e0b`)

`app/main.py` lifespan now `aclose()`es the shared `redis.asyncio` client (rate limiter + stream fan-out + ticket store) on shutdown instead of abandoning it to GC; stale M1/M2 placeholder comments deleted. Test asserts the client is closed when the lifespan exits.

### 4. Style fixup (`7d8ce3a`) — line-length gate on the new test module.

## Verification

| Gate | Result |
|---|---|
| `pytest` (full backend suite) | pass — see PR checks (2,8xx tests; relay tests additionally 30× locally) |
| `ruff check .` / `ruff format --check .` | pass |
| `mypy` | pass (211 source files, no issues) |
| `lint-imports` | pass (2 contracts kept) |
| Red-proof | relay regression test demonstrated failing against pre-fix handler |

## Risks

- **Credential-surface change (highest-risk part of the wave).** `_read_live` now decrypts device credentials in the api process. Mitigations: it reuses the existing audited `credentials.decrypt` path with `target=` scope enforcement (no new crypto or bypass); the plaintext lives only in a local `SshParams` (repr-redacted) for the session's duration — the same in-memory exposure profile as the config/discovery workers; error strings carry exception class + message only, and the tests assert the secret never appears in surfaced errors.
- **Event-loop pressure.** Live reads open blocking SSH sessions from the api process via `asyncio.to_thread` (bounded by the default thread-pool). A burst of concurrent live reads could saturate the pool. Acceptable at current scale; see follow-ups.
- **Relay restructure touches every WS stream.** The drain semantics are behavior-preserving for the happy path (same cadence, same dedup); the changed path is idle-then-frame, which was previously broken. The full WS test class (19 tests incl. 2 new) passes; risk is bounded by the DB-replay fallback that continues to guarantee completeness.
- **Netmiko driver-name fix changes worker behavior for junos/fortios** (previously guaranteed-invalid device_type → now correct driver). Strictly an improvement, but live SSH against those vendors has no lab coverage in CI (unchanged for cisco/eos, which the conformance suites pin).

## Remaining issues (known, out of Wave 1 scope)

- A non-`NetOpsError` exception escaping a capability (e.g. a garbage `device_type` credential override raising `ValueError` inside netmiko) still propagates out of the tool rather than becoming `{"error": ...}` — same exposure as the pre-existing worker paths; the agent framework surfaces it as a tool failure.
- Live reads are SSH-only, mirroring `CredentialKind.SSH`; API-driven vendors (panos/fortios REST) have live-read capability classes but no API-credential path here.
- The `KeyError: 'event'` flake variant recorded in the memo traced to the same dead-relay mechanism; if any *distinct* terminal-ordering variant ever reappears, treat it as a new bug — the rerun-to-green habit is retired with this fix.
- `pending_live` teardown suppresses the pending task's `CancelledError`; in the rare case the handler task itself is cancelled at that exact await, cancellation still propagates via the outer scope (FastAPI closes the socket), but the interaction is untested.

## Suggested follow-up work

1. **Wave 2 items as planned** (ErrorBoundary, single-flight refresh → reuse detection, quickstart security headers, CORS, compose pins, kind-gate promotion).
2. **Live-read concurrency budget:** a small semaphore around `_connect_and_read` (per-process cap) before the Troubleshooting Agent is exercised by many concurrent sessions.
3. **API-credential live reads** for the REST-first firewall vendors, reusing the same scope-enforced decrypt path.
4. **Wrap unexpected capability exceptions** into the `{"error": ...}` contract at the `_read_live` boundary (one `except Exception` with class-name-only formatting) — needs a deliberate decision because it broadens an exception handler on a secret-adjacent path.
5. **Backport the pending-task drain pattern** anywhere else `asyncio.wait_for` wraps an async generator's `__anext__` (repo grep found no other site, but the pattern is worth a lint note in `docs/`).
