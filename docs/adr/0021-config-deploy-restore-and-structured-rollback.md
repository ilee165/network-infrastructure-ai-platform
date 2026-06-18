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
- **Verify-after:** re-capture the running config and assert the intended end-state.
  - *Restore success predicate:* the post-change running config normalizes equal to the restored snapshot (exit criterion "device config matches the snapshot afterward").
  - *Deploy success predicate:* the device is still reachable / the session re-establishes **and** the re-captured running config, normalized, contains every line of the applied fragment with no unintended residual diff outside the fragment's scope (the target lines are present and nothing else changed unexpectedly). This is the asserted, tested deploy post-condition — symmetric in rigor with the restore predicate, not merely "lines present + reachable."
- **Rollback on failure:** if apply errors or verify-after fails, the executor restores the captured pre-change baseline (vendor-native mechanism, §4), then **verifies the rollback** before declaring success.
  - *Rollback success criterion (both restore and deploy, symmetric with the restore exit criterion):* after baseline replay, re-capture the running config and assert it normalizes **equal to the captured pre-change baseline**. Only then does the CR transition `failed → rolled_back` (ADR-0020) with before/after audited.
  - For the deploy case specifically: a baseline replay of a partially-applied, order-sensitive or stateful fragment (§4 `cisco_ios`, §5) may not reproduce the exact baseline. If the re-captured config does **not** normalize equal to the baseline, the rollback is treated as **rollback-failed** — the CR stays `failed` and an operator alert is raised (it is never silently closed and never reported as `rolled_back`). Rollback success is thus an asserted equality, not an assumption, on the same footing as the restore exit criterion.

### 4. Vendor-native apply/rollback mechanics

| Plugin | Apply | Native rollback primitive |
|---|---|---|
| `cisco_ios` | enter `configure terminal`, send lines | `configure replace` where available; otherwise replay of the captured pre-change baseline as the inverse (IOS lacks transactional commit) — the captured baseline is the safety net |
| `cisco_iosxe` | `configure terminal` / config session | **`configure replace flash:<baseline>` + `configure confirm`** (commit-confirm / rollback timer) — the strongest of the three |
| `eos` | config **session** (`configure session <id>`) | `commit` / `abort`; commit-timer auto-rollback if not confirmed — session model gives atomic apply + native abort |

`cisco_ios` is certified first against the conformance suite (M5 task #5); `cisco_iosxe` and `eos` mirror it (task #6). Where a vendor offers commit-confirm (IOS-XE, EOS), the executor uses it so a connectivity-breaking change auto-reverts even if the worker loses the session.

- **`cisco_ios` reachability-loss handling (the "reversible by construction" hole on the one platform without commit-confirm).** Classic IOS has no commit-confirm: rollback is a worker-initiated replay of the captured baseline over the netmiko session. If the change severs the management path mid-apply (an ACL on the mgmt interface, shutting the uplink, changing the mgmt VLAN/IP), the worker can no longer reach the device to replay the baseline and the device is stranded — replay is not merely non-atomic but *impossible*. Because this is the single highest-blast-radius operation in the project, M5 handles it as follows:
  1. **Dead-man auto-revert where the image supports it (preferred).** Before applying a `cisco_ios` change, the executor arms a device-side timed revert to the captured baseline — `configure replace <baseline> ... commit timer` (the IOS reload/rollback-timer form) on images that have it, or an EEM/kron-scheduled `configure replace` of the baseline — and disarms it only after verify-after confirms reachability. This gives classic IOS a commit-confirm-equivalent so a connectivity-severing change auto-reverts even when the worker loses the session.
  2. **Management-path guardrail on images without a dead-man primitive.** If the running image offers no such timed-revert mechanism, the deploy/restore fragment validation **rejects** any change touching the management path (mgmt-interface ACLs, the mgmt interface/uplink admin state, the mgmt VLAN/IP, or the line/transport that carries the session) on `cisco_ios`. Such changes are **out of M5 scope** for classic IOS and require a console/OOB-fallback path documented for the operator.
  3. **Unreachable rollback is never silent success.** A rollback that cannot reach the device (replay impossible because reachability is gone, and no device-side dead-man revert fired) is treated as the **rollback-failed → CR stays `failed` → operator alert** path of §3 — explicitly *not* reported as `rolled_back` and never silently closed.

### 5. Idempotency & verification

- Restore is naturally idempotent (replaying the same snapshot onto a matching device is a no-op diff); the executor computes the pre-apply diff and, if empty, completes the CR without touching the device (logged as a no-op apply).
- Deploy idempotency is best-effort: the pre-apply diff shows what will change; re-applying an already-present fragment yields an empty diff and a no-op. Verify-after is the authoritative success signal, not the apply return code.

## Consequences

**Positive**
- Every device write is reversible by construction: a fresh pre-change baseline plus a vendor-native rollback primitive means a broken change returns the device to its exact prior running state without manual re-entry — including on classic `cisco_ios`, where §4's dead-man auto-revert (or, absent the primitive, the management-path guardrail) closes the one case the captured-baseline replay cannot cover: loss of reachability to the device mid-apply.
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
