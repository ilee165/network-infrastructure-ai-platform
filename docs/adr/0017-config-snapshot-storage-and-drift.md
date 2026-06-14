# ADR-0017: Configuration Snapshot Storage and Drift Detection

**Status:** Accepted | **Date:** 2026-06-14 | **Milestone:** M4 (new capability — `REPO-STRUCTURE.md` §6)

## Context

CLAUDE.md "Config Management" requires **Backup**, **Drift detection**, and **Compliance checks** (MVP M4; Restore is M5 behind ChangeRequest). The `config_snapshots` and `compliance_policies` tables are already declared in ADR-0004 §2; this ADR fixes *how* snapshots are stored, diffed, and exposed to agents.

A device configuration is **secret-bearing**: it contains enable secrets (type-7/9), SNMP community strings, IPsec/BGP/RADIUS keys, and local user hashes. Three forces collide:

- **Drift fidelity** — drift = current config vs. last-approved baseline as a unified diff; this requires byte-stable, verbatim content. Redacting at capture would hide drift on exactly the security-relevant lines.
- **Future restore (M5)** — `CONFIG_RESTORE` (ADR-0011, M5) must replay a real, complete config; a redacted snapshot is unrestorable.
- **Secure by default / Explain AI decisions** — config content must never leak into an LLM prompt with secrets intact, yet the Configuration Agent must *explain* a drift diff.

## Decision

**Store configuration snapshots verbatim and content-addressed, governed like `raw_artifacts` (RBAC + append-only audit), and apply the A9 redaction layer only at the LLM boundary — never at rest.**

1. **`config_snapshots` (per ADR-0004):** columns include `device_id`, `captured_at`, `content_hash` (SHA-256 of normalized text — content-addressed dedup: an unchanged config re-capture stores no new blob, only a new observation row), `content` (verbatim config text), `source` (`scheduled` | `on_demand`), `capture_run_id`, and a `baseline` marker (the current last-approved config per device). Retention is a configurable setting (count + age); enforced by a `config`-queue cleanup task, tombstoned + audited like other retention jobs.

2. **Raw at rest, behind RBAC + audit.** Snapshots are stored verbatim — the same posture `raw_artifacts` already carry (ADR-0004 §2). The `config-snapshots` resource requires `engineer`+ to read content; every read/decrypt-equivalent access is an `audit_log` entry. No envelope encryption at rest in M4 (parity with `raw_artifacts`); at-rest encryption of secret-bearing artifacts is tracked as a single production-hardening item covering both tables, not a M4 split.

3. **Redaction at the LLM boundary only (A9).** Any path that puts config content into a model prompt — the Configuration Agent's drift-explanation / compliance-summary tools — routes the content through `llm/redaction.py` first (the M3 mandatory redaction layer), stripping the secret patterns it already knows (SNMP communities, type-7/9, BGP/RADIUS keys, SNMPv3). The agent explains diffs over redacted text; secrets never reach any provider. Diff/compliance computation runs over the *raw* text server-side (no redaction), preserving fidelity.

4. **Drift detection (`engines/config_mgmt/`).** Drift = unified diff (`difflib`) of the device's current snapshot against its `baseline` snapshot; a non-empty diff is a drift event with the changed hunks recorded. Establishing/approving a new baseline is an explicit action (audited); until then the last-approved baseline stands.

5. **Capture (`config` queue, ADR-0008).** `CONFIG_BACKUP` plugin capability (IOS/IOS-XE/EOS) returns verbatim config; the engine hashes, dedups, and stores it. Scheduled (Celery beat) nightly + on-demand; per-device fan-out with retries; failures surface in job status and are audited.

## Consequences

**Positive**
- Drift detection is faithful — secret-line changes (a new SNMP community, a changed enable secret) are detected, which is precisely what a security-relevant drift check must catch.
- M5 `CONFIG_RESTORE` has a complete, real config to restore.
- Content-addressing bounds storage growth (unchanged configs cost one row, not one blob) and gives a natural snapshot identity.
- The secret boundary is the existing, tested A9 layer — one place to reason about leakage, exercised by the M3 redaction eval pattern.

**Negative**
- Secret material sits in Postgres at rest (behind RBAC + audit) — same residual risk as `raw_artifacts` today; mitigated, not eliminated, until the production at-rest-encryption item lands.
- Drift over very large configs produces large diffs; the engine stores hunks, not whole re-copies, to bound this.

## Alternatives considered

1. **Envelope-encrypt snapshot content at rest** (like `device_credentials`). Rejected for M4: adds key-management + a decrypt step to every diff/compliance read for parity-only benefit with `raw_artifacts`, which are *not* encrypted; deferred to a single production item covering all secret-bearing artifacts.
2. **Redact secrets at capture, before storage.** Rejected: destroys drift fidelity on the most security-relevant lines and makes M5 restore impossible.
3. **Store only diffs, no full snapshots.** Rejected: breaks restore and makes re-baselining/full-config compliance checks impossible; content-addressing already de-duplicates unchanged captures.
