# ADR-0021: Config Deploy/Restore and Structured Rollback

**Status:** Accepted | **Date:** 2026-06-18 | **Milestone:** M5 (new capability — `REPO-STRUCTURE.md` §6; first device write path)

## Context

ADR-0017 (M4) stores verbatim, content-addressed `config_snapshots` and detects drift, explicitly deferring **Restore** to M5 "behind a ChangeRequest." ADR-0006 already declares the `CONFIG_RESTORE` and `CONFIG_DEPLOY` capability enum members; M5 builds the typed interfaces and the three implementations. MVP.md §7 scopes the route/switch plugins **`cisco_ios`, `cisco_iosxe`, `eos`** (NX-OS/JunOS/PAN-OS are production-roadmap). These are the first operations that **mutate a real device**, so the blast radius is maximal and the security bar is highest in the project.

Two forces shape this ADR: (a) a config write must be **reversible** — if an apply half-lands or breaks reachability, the device must return to its prior state without a human re-typing config; (b) the write must be **gated** — it may only ever happen as the execution step of an `approved` ChangeRequest (ADR-0020), run by the Automation Agent (M5 task #9), never directly from a tool call.

## Decision

**`CONFIG_RESTORE` (replay an existing M4 `config_snapshot`) and `CONFIG_DEPLOY` (apply a supplied config fragment) are typed plugin capabilities that execute on `cisco_ios`/`cisco_iosxe`/`eos` only as the execution step of an `approved` ChangeRequest. Before any write, the worker captures a fresh pre-change snapshot as the rollback baseline; after the write it verifies the result; on failure it invokes a structured per-change rollback to that baseline.**

### 1. Capability interfaces (`plugins/base.py`)

- `ConfigRestoreCapability.restore(snapshot: ConfigSnapshot, *, plan: ChangePlan) -> ChangeResult`
- `ConfigDeployCapability.deploy(config_fragment: str, *, plan: ChangePlan) -> ChangeResult`

Both consume a `ChangePlan` carrying the originating `change_request_id`, the captured pre-change baseline reference, and idempotency metadata; both return a `ChangeResult` (applied diff, post-verify outcome, rollback outcome if any). They live behind the registry like every capability (ADR-0006 §4) and re-derive verbatim device output to `raw_artifacts` first.

### 2. Execution path — only via an approved ChangeRequest

- Writes run on the **`config` queue** (ADR-0008) inside the **Automation Agent** executor (ADR-0020 §1 `approved → executing`). The capability methods refuse to run unless invoked with a `ChangePlan` whose CR is in `executing` state (claimed from `approved`). A direct tool call to a deploy/restore capability outside the CR executor is a typed `PluginError` — there is no other caller.
- The `payload` the approver reviewed (ADR-0020 §2, frozen at submit) is exactly what is rendered to the device — no re-render between approval and apply.

### 3. Structured per-change rollback

- **Capture-before (baseline):** immediately before the write, the executor runs `CONFIG_BACKUP` (ADR-0017 §5) against the live device and pins that snapshot as the CR's rollback baseline. This is the *actual* running state at apply time — preferred over the CR's `rollback_plan` reference, which may be stale if the device drifted since submit (drift between submit and execute is itself surfaced and can fail the apply pre-check).
- **Apply** the change (restore = replay snapshot text; deploy = merge the fragment) over the D7 netmiko session, capturing per-block results.
- **Verify-after:** re-capture the running config and assert the intended end-state (for restore: the post-change running config normalizes equal to the restored snapshot — exit criterion "device config matches the snapshot afterward"; for deploy: the target lines are present and the device is still reachable / session re-establishes).
- **Rollback on failure:** if apply errors or verify fails, the executor restores the captured pre-change baseline (vendor-native mechanism, §4), transitions the CR `failed → rolled_back` (ADR-0020), and audits before/after. A rollback that itself fails leaves the CR `failed` and raises an operator alert (never silently closed).

### 4. Vendor-native apply/rollback mechanics

| Plugin | Apply | Native rollback primitive |
|---|---|---|
| `cisco_ios` | enter `configure terminal`, send lines | `configure replace` where available; otherwise replay of the captured pre-change baseline as the inverse (IOS lacks transactional commit) — the captured baseline is the safety net |
| `cisco_iosxe` | `configure terminal` / config session | **`configure replace flash:<baseline>` + `configure confirm`** (commit-confirm / rollback timer) — the strongest of the three |
| `eos` | config **session** (`configure session <id>`) | `commit` / `abort`; commit-timer auto-rollback if not confirmed — session model gives atomic apply + native abort |

`cisco_ios` is certified first against the conformance suite (M5 task #5); `cisco_iosxe` and `eos` mirror it (task #6). Where a vendor offers commit-confirm (IOS-XE, EOS), the executor uses it so a connectivity-breaking change auto-reverts even if the worker loses the session.

### 5. Idempotency & verification

- Restore is naturally idempotent (replaying the same snapshot onto a matching device is a no-op diff); the executor computes the pre-apply diff and, if empty, completes the CR without touching the device (logged as a no-op apply).
- Deploy idempotency is best-effort: the pre-apply diff shows what will change; re-applying an already-present fragment yields an empty diff and a no-op. Verify-after is the authoritative success signal, not the apply return code.

## Consequences

**Positive**
- Every device write is reversible by construction: a fresh pre-change baseline plus a vendor-native rollback primitive means a broken change returns the device to its exact prior running state without manual re-entry.
- Commit-confirm on IOS-XE/EOS protects against the worst case — a change that severs the management session — via device-side auto-revert.
- Reusing M4's `CONFIG_BACKUP`/`config_snapshots` machinery for both the restore source and the rollback baseline means no new snapshot storage (M5-PLAN baseline note) and one tested capture path.
- Verify-after makes "the device matches the snapshot" an asserted, tested post-condition (exit criterion), not an assumption.

**Negative**
- Classic IOS has no transactional commit; rollback there is a replay of the captured baseline, which is correct but not atomic — a mid-apply failure can leave a transient inconsistent state until the baseline replay completes (bounded, audited, alert-on-rollback-failure).
- Pre-change live capture adds a round-trip and a snapshot per execution — accepted: it is the safety net and is content-addressed (ADR-0017 dedups unchanged content).
- Deploy idempotency is fragment-dependent; a fragment with order-sensitive or stateful commands may not be cleanly re-appliable — mitigated by verify-after as the source of truth and by the approver reviewing the exact diff.

## Alternatives considered

1. **NAPALM `config_replace` as the universal apply/rollback engine.** Rejected as the contract (consistent with ADR-0006 alt #1): NAPALM's replace model does not map onto our ChangeRequest lifecycle and misses most of our vendor matrix; a plugin *may* use it internally where its driver helps, but the public capability contract and rollback semantics are ours.
2. **No pre-change capture — rely on the CR's `rollback_plan` snapshot reference.** Rejected: that reference can be stale (device drifted since submit); rolling back to a stale baseline could undo unrelated legitimate changes. Capture-at-apply reflects true current state.
3. **Best-effort apply with no verify-after.** Rejected: an apply return code does not prove the intended end-state (or continued reachability). Verify-after is what makes the exit criterion testable and catches connectivity-breaking changes.
4. **Allow direct deploy/restore tool calls (gate only at the agent layer).** Rejected: a second write path that bypasses the CR spine reintroduces the exact risk ADR-0020 eliminates. The capability refuses to run outside an `executing` CR.
