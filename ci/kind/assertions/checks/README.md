# kind assertion checks (W4-T4 / W4-T5 plug-in point)

This directory is the extension point of the W4-T3 assertion-runner
(`../run-assertions.sh`). It is intentionally empty of checks in W4-T3 — the
harness + runner scaffold lands first, then the two enforcement tasks add their
assertions here:

- **W4-T4 (mTLS)** drops a check (e.g. `mtls-postgres.sh`) that uses
  `assert_handshake_ok` / `assert_handshake_refused` from `../lib.sh` to prove a
  valid-cert client handshakes and a plaintext / wrong-CA client is **refused**
  (ADR-0039 §6).
- **W4-T5 (collector egress)** drops a check (e.g. `collector-egress.sh`) that
  uses `assert_egress_allowed` / `assert_egress_blocked` to prove a mgmt-subnet /
  named-service egress **succeeds** and an arbitrary external egress is
  **blocked** (ADR-0041 §3).
- **W4-T3 (Postgres failover drill)** — `pg-failover.sh` (+ `pg-failover-drill-probe.yaml`):
  the G-REL §316 failover drill. It seeds hash-chain-valid audit-shaped rows on the
  quorum-sync audit path, **KILLs the CNPG primary**, and asserts **automated
  promotion + write service ≤ 60 s (RTO measured from the kill)** and **zero
  committed-audit loss** on the promoted primary (row COUNT + the specific
  last-before-kill row present + no `seq` gap + hash-chain intact — real PG, never
  SQLite; ADR-0042 §2/§3, ADR-0038 §1). It **SKIPs loudly** on a non-HA run (no CNPG
  `Cluster`) so a missing cluster is never a false-green. Its **negative control**
  (`PG_FAILOVER_DRILL_NEGATIVE_CONTROL=1` → the last row commits async and is lost →
  RED) is **proven to bite** hardware-free by `../../selftest/pg-failover-bite.sh`
  (ADR-0047 §2). Runs on the **HA** path only (`HA=1 ci/kind/kind-harness.sh`);
  live-run is CI-only (L1) and signal-only (absent from `all-gates`).

## Contract for a check

1. It is an executable `*.sh` file in this directory.
2. It sources the shared helpers: `. "$(dirname "$0")/../lib.sh"`.
3. It performs its assertions via the `assert_*` helpers. On any failure it
   either **exits non-zero** explicitly or simply **leaves a non-zero
   `assert_failures`** — `lib.sh` installs an `EXIT` trap in the check's
   subprocess that converts a recorded `assert_failures` into a non-zero exit, so
   both paths reach the runner. The runner treats a non-zero exit OR an empty log
   as a failed check (no silent no-op). A check may still end with
   `exit "$(assert_failures)"` for explicitness, but it is no longer required.
4. It assumes the chart is already applied and the **CNI self-test has passed**
   (the harness guarantees both before invoking the runner — ADR-0041 §2/§3).

The runner discovers every `*.sh` here in sorted order, runs each under
`set -o pipefail`, and exits non-zero if any check fails.
