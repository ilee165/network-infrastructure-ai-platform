# Runbook — Ephemeral in-CI kind cluster harness (W4-T3)

> Operator/developer procedure for the ADR-0041 §2/§3 + ADR-0039 §6 kind harness: how it brings up a throwaway cluster with an **enforcing CNI**, proves the CNI actually enforces NetworkPolicy (the **CNI self-test bite**), applies the chart, and runs the assertion-runner that **W4-T4 (mTLS handshake)** and **W4-T5 (collector egress deny)** plug their assertions into. Records that the P2 live kind job's promotion to a **blocking gate** for the two named G-SEC sub-items (mTLS handshake + collector egress deny) is **AUTHORED but HELD** — per ADR-0048 §4 the promotion is gated behind an EXECUTED plant→red→revert bite on a CI ubuntu runner, which (per P1-W4-LESSONS L1: kind cannot run on the authoring host) has **not run yet**; until it does the live step stays `continue-on-error` and out of `all-gates` (see "Gate status" below). The `kind-harness-ha` HA live job likewise stays non-blocking. Cheap-scope only — handshake + deny; HA/scale/soak are P3-Platform.

## Objective

Give the two W4 enforcement tasks a deterministic, hardware-free place to BITE: an ephemeral kind cluster running an enforcing CNI so a default-deny NetworkPolicy is actually enforced (kind's default `kindnet` admits but does NOT enforce NetworkPolicy — ADR-0041 §2). Without the enforcing CNI + the self-test, every downstream deny assertion is false-green (P1-W4-LESSONS **L1** — the single biggest risk in this wave).

## Facts

| Field | Value |
|---|---|
| ADRs | ADR-0041 §2/§3 (enforcing CNI + CNI self-test + deny bite), ADR-0039 §6 (mTLS handshake bite), ADR-0029 (chart hardening + manifest gates) |
| Harness entrypoint | `ci/kind/kind-harness.sh` |
| kind config | `ci/kind/kind-config.yaml` (`disableDefaultCNI: true` — the load-bearing line) |
| Enforcing CNI | Calico `v3.28.2` (pinned; `CALICO_VERSION` override) |
| CNI self-test | `ci/kind/cni-selftest/probe.yaml` + `default-deny.yaml` |
| Assertion-runner | `ci/kind/assertions/run-assertions.sh` (discovers `checks/*.sh`, exits non-zero on any failure) |
| Assertion helpers | `ci/kind/assertions/lib.sh` (`assert_egress_allowed/blocked`, `assert_handshake_ok/refused`, `run_in_pod`) |
| T4/T5 plug-in | `ci/kind/assertions/checks/` (T4 drops `mtls-*.sh`, T5 drops `collector-egress*.sh`) |
| Static validator | `ci/kind/selftest/validate-harness.sh` (no cluster; asserts the harness invariants incl. the W4-T1 HA add-on — the policy-as-test bite) |
| CI job (P2) | `.github/workflows/ci.yml` job `kind-harness` (**signal-only / non-blocking live** — promotion AUTHORED but HELD pending the ADR-0048 §4 bite proof; step stays `continue-on-error`, NOT in `all-gates` needs; see "Gate status" below) |
| CI job (HA, P3 W4-T1) | `.github/workflows/ci.yml` job `kind-harness-ha` (**non-blocking live** — see "HA topology" + "Gate status") |
| Cluster name | `netops-w4` (`CLUSTER_NAME` override) |
| HA operator installer | `ci/kind/ha/install-operators.sh` (CloudNativePG `1.29.1` + KEDA `2.16.1`, pinned; `CNPG_VERSION`/`KEDA_VERSION` override) |
| HA readiness gate | `ci/kind/ha/wait-ha-ready.sh` (a half-up topology must NOT read ready — L5) |
| HA overlay validator | `ci/kind/ha/validate-ha-overlay.sh` (static render + reduced-scale count bite) |
| Reduced-scale HA overlay | `deploy/kubernetes/netops/values-kind-ha.yaml` (`HA_VALUES` override) |
| Postgres failover drill (P3 W4-T3) | `ci/kind/assertions/checks/pg-failover.sh` + `pg-failover-drill-probe.yaml` (G-REL §316 — runs on the HA path via the assertion-runner) |
| Failover drill bite proof (P3 W4-T3) | `ci/kind/selftest/pg-failover-bite.sh` (hardware-free negative-control plant→red→revert; runs in `kind-harness-ha`, no cluster) |

## How the harness runs (`kind-harness.sh`)

1. **Bring-up.** `kind create cluster --config ci/kind/kind-config.yaml`. The config sets `disableDefaultCNI: true`, so the cluster comes up with NO CNI and nodes stay `NotReady` until step 2.
2. **Install the enforcing CNI (Calico).** `kubectl apply -f <pinned calico.yaml>`, then `kubectl rollout status daemonset/calico-node` and `kubectl wait --for=condition=Ready nodes`. This is the load-bearing step (ADR-0041 §2).
3. **CNI self-test (the bite).** In a throwaway `cni-selftest` namespace: apply a hardened probe pod, confirm a known egress (`1.1.1.1:53`) **SUCCEEDS** (baseline), then apply a default-deny egress policy selecting the probe and confirm the SAME egress is now **BLOCKED** (with a short retry for dataplane programming). If it is not blocked, the CNI admits but does not enforce NetworkPolicy → the harness **exits non-zero** and the run fails. The self-test namespace is then deleted.
4. **Render + apply the chart.** `helm template netops … | tr -d '\r' > rendered` (pipefail + `test -s`), then `kubectl apply` into the `netops` namespace. (CRD-dependent objects — cert-manager / Kyverno — are owned by W4-T4/T5, which install their prerequisites; the scaffold warns and continues.)
5. **Run the assertion-runner.** `bash ci/kind/assertions/run-assertions.sh`. It runs every `checks/*.sh` under pipefail, treating a non-zero exit OR an empty log as a failed check, and exits non-zero if any check fails. With no checks present (W4-T3 scaffold) it exits 0 with a loud "nothing to assert" note.
6. **Teardown.** A `trap teardown EXIT INT TERM` deletes the cluster on EVERY exit — success, failure, or signal — so no ephemeral cluster leaks. `KEEP_CLUSTER=1` skips teardown for local debugging.

## Running it locally

```bash
# Prereqs: a Docker (or Podman) backend, kind, kubectl, helm on PATH.
ci/kind/selftest/validate-harness.sh     # static — no cluster; should pass (incl. HA invariants)
ci/kind/ha/validate-ha-overlay.sh        # static — helm only; reduced-scale HA render + count bite
ci/kind/kind-harness.sh                  # P2 full live run (≈3-6 min)
HA=1 ci/kind/kind-harness.sh             # + reduced-scale HA topology (CNPG + KEDA + Sentinel) (≈8-15 min)
KEEP_CLUSTER=1 HA=1 ci/kind/kind-harness.sh   # keep the HA cluster up to poke at it
kind delete cluster --name netops-w4     # manual teardown after KEEP_CLUSTER
```

## How W4-T4 / W4-T5 add assertions

Drop an executable `*.sh` into `ci/kind/assertions/checks/` that sources `../lib.sh` and asserts via the helpers (see `checks/README.md` for the contract). The runner picks it up automatically. Examples:

- **W4-T4 mTLS** — `assert_handshake_ok` (valid-cert client connects) and `assert_handshake_refused` (plaintext / wrong-CA client is rejected by Postgres; ADR-0039 §3/§6).
- **W4-T5 egress** — `assert_egress_allowed` (mgmt-subnet / named service reachable) and `assert_egress_blocked` (arbitrary external destination denied; ADR-0041 §3). These are meaningful ONLY because step 3 proved the CNI enforces.

## HA topology (P3 W4-T1) — the ephemeral HA substrate the W4 drills run on

The P2 harness above brings up a **single-node, enforcing-CNI** cluster for the
mTLS + collector-egress assertions. **W4-T1 (ADR-0047 / ADR-0048 §3)** *extends*
that same harness with an **`HA=1` add-on path** that stands up the reduced-scale
**HA topology** the W4 reliability/scale drills (T3–T8) and the gate promotion
(T2) run against — **without touching** the P2 CNI self-test or the mTLS /
collector assertions (they run unchanged alongside).

### Components the HA path adds

| Component | What / where | ADR |
|---|---|---|
| **CloudNativePG operator** | installed by `ci/kind/ha/install-operators.sh` (pinned `1.29.1` — supported release with the CVE-2026-44477 fix; 1.24.x is EOL/unpatched), so a CNPG `Cluster` (1 primary + 2 replicas) + `Pooler` can run on kind | ADR-0042 |
| **KEDA** | installed by the same script (pinned `2.16.1`), so per-queue worker `ScaledObject`s + `TriggerAuthentication`s resolve | ADR-0043 |
| **Redis Sentinel** | deployed by the chart via the HA overlay (1 primary + 2 replicas, 3 Sentinels, 2-of-3 quorum, AOF) | ADR-0044 |
| **Enforcing CNI** | **REUSED** — the existing Calico bring-up + CNI self-test in `kind-harness.sh` (NOT duplicated) | ADR-0041 §2 |
| **netops chart @ reduced scale** | rendered with `-f values-kind-ha.yaml` layered on the defaults + the mTLS path | ADR-0047 §1 |

### Reduced-scale replica counts (ADR-0047 §1 posture — NAMED, not certified)

The HA path proves the HA **mechanisms** stand up on a single kind node; it does
**not** certify a scale point (the certified-scale numbers stay deferred-accepted
→ GA per ADR-0047 §4). The exact counts it runs at:

| Tier | Count | Note |
|---|---|---|
| **CloudNativePG Postgres** | **1 primary + 2 replicas** (`instances: 3`) | ADR-0042 §1 quorum **minimum** — not reduced (the failover drill needs a real quorum) |
| **PgBouncer pooler** | **1 instance** | reduced from GA 2; one pod proves the transaction-mode path on a single node |
| **Redis (Sentinel-managed)** | **1 primary + 2 replicas** (`replicas: 3`) | ADR-0044 §1 minimum — not reduced |
| **Sentinels** | **3**, quorum **2-of-3** | ADR-0044 §1 odd-majority minimum — not reduced |
| **api** | HPA **min 2 / max 4** | floor **2 stays** (HA floor, chart refuses < 2); ceiling reduced to 4 for one node |
| **KEDA per-queue workers** | discovery/config **min 1 max 2**, docs **min 0 max 1**, packet_capture/packet_analysis **min 0 max 1** | reduced ceilings; per-queue isolation mechanism unchanged; packet queues stay sandbox-pinned |
| **base worker / frontend / neo4j** | **1** each | single Neo4j + automated rebuild (Community has no clustering) |

Only the resource requests + the **elastic ceilings** (HPA/KEDA `maxReplicas`,
pooler instances) are pulled down for the node. The **quorum minima** (CNPG 3,
Sentinel 3/2-of-3) are **not** reduced — lowering them would break the mechanism
the drills exercise, not "reduce scale".

### How the HA path runs (`HA=1 ci/kind/kind-harness.sh`)

1. **Steps 1–3 (unchanged):** create the cluster, install Calico, run the **CNI
   self-test bite**, delete the self-test namespace.
2. **Install HA operators** (only when `HA=1`, **after** the CNI self-test,
   **before** the chart render so the CRDs exist when applied): CNPG operator +
   KEDA, both **pinned** (never `latest`), applied **server-side** (idempotent +
   re-appliable), **retried** on a transient fetch/apply failure, and
   **readiness-gated** — the script waits for each operator's CRDs to be
   `Established` and its controller Deployment to be `Available` before returning.
3. **Render + apply** the chart with `-f values-kind-ha.yaml` layered on (the
   reduced-scale HA tiers + the mTLS path). `pipefail` + `test -s` on the render.
4. **Gate on HA readiness** (`wait-ha-ready.sh`): the CNPG `Cluster` reports the
   full `readyInstances` count **and** a `currentPrimary`; the Redis + Sentinel
   StatefulSets are fully rolled out; every Deployment (api HPA-floor-2, workers,
   KEDA per-queue) is Available; every KEDA `ScaledObject` reconciled `Ready`. A
   **half-up** topology **HARD-FAILS** here — it must **not** read "ready" (**L5**;
   the ADR-0048 §3 reliability prerequisite for W4-T2 promotion).
5. **Assertion-runner + teardown (unchanged):** the P2 mTLS + collector assertions
   run, then the trap tears the cluster down on any exit.

## Postgres failover drill (P3 W4-T3, G-REL §316) — the reliability drill on this HA topology

The HA topology above is the substrate a set of **reliability/scale drills**
(ADR-0047) run against. **W4-T3** implements the first one: the **Postgres
failover drill** (`ci/kind/assertions/checks/pg-failover.sh`). It plugs into the
same assertion-runner, so on the **HA path** (`HA=1 ci/kind/kind-harness.sh`) it
runs automatically after the HA-readiness gate — no separate invocation.

### §11 criterion + target (ADR-0042 §2/§3/§7, ADR-0047 §3)

| Gate / line | Target (reduced-scale run) |
|---|---|
| **G-REL §316** | primary kill → **AUTOMATED promotion, write service restored ≤ 60 s** (RTO measured **from the kill**, not from detection) **AND zero committed-audit-entry loss** — every audit row committed before the kill is present on the promoted primary, **hash-chain-valid, no `seq` gap** (the ADR-0042 §2 quorum-sync audit-write guarantee). Asserted on **real PG** (the kind CNPG cluster), never SQLite (ADR-0047 §5). |

### What the drill does

1. **Precondition / SKIP.** If no CNPG `Cluster` is present (a non-HA run) the drill
   **SKIPs loudly** (`exit 0`) — a missing cluster is never a false-green pass.
2. **Seed.** Creates a drill-scoped audit-shaped table (`seq` + `prev_hash`/
   `entry_hash` chain) and seeds `SEED_ROWS` (default **25**) hash-chain-valid rows,
   each committed on the **quorum-sync audit path** (`SET LOCAL
   synchronous_commit=remote_apply`, ADR-0042 §2) through the CNPG **`-rw`** Service.
   Then commits one **last-before-kill** row (the row the negative control loses).
3. **Kill.** `kubectl delete pod <currentPrimary> --force --grace-period=0` — the
   **RTO clock starts at the kill** (§316 measures from the kill, not detection).
4. **Measure.** Polls the `-rw` Service until a **write** succeeds on a **new**
   primary (operator-elected, different from the killed pod) → **RTO = restore
   epoch − kill epoch**; asserts **RTO ≤ 60 s** and that the promotion was automated.
5. **Zero-loss.** On the promoted primary asserts: row **COUNT** = all committed
   rows (no loss), the **last-before-kill row present**, **no `seq` gap** (append
   order contiguous), and the surviving **hash-chain intact** (every `prev_hash`
   links its predecessor `entry_hash`; genesis first — ADR-0038 §1).

### Reduced scale (STATED) + named ceiling (ADR-0047 §1/§4)

The drill proves the **failover + zero-audit-loss mechanism** bites at reduced
scale: **CNPG `instances: 3`** (1 primary + 2 replicas — the ADR-0042 §1 quorum
**minimum**, *not* reduced) and **~25 seeded rows**, RTO budget **60 s** from kill.
It does **not** certify a scale point. The certified-scale ceilings — a
**backups-only DR** restore onto a clean cluster (G-REL §318: RPO ≤ 5 min / RTO ≤
1 h) and the **30-day soak** (G-REL §315) — stay **deferred-accepted → GA** with the
ADR-0047 §4 written promotion path; they are **never claimed** from this run.

### Negative control — PROVEN to bite (ADR-0047 §2)

Every drill ships a planted regression that turns its assertion **RED**, shown to
bite before it is trusted. For the failover drill:

| Positive assertion | Planted negative control (turns it RED) |
|---|---|
| primary kill → promote ≤ 60 s; every committed audit row survives, hash-chain-valid, no `seq` gap | **async / non-quorum commit** on the audit path (`PG_FAILOVER_DRILL_NEGATIVE_CONTROL=1` → the last row commits `synchronous_commit=off`) → a just-committed audit row is **lost** on the promoted primary → the zero-loss COUNT + last-row + seq-gap assertions go **RED** |

**How the bite is proven WITHOUT a cluster (L1).** The live drill runs only on the
kind CNPG cluster, which cannot run on the authoring host (Windows, no Docker/Linux
kind). `ci/kind/selftest/pg-failover-bite.sh` earns the ADR-0047 §2 plant→red→revert
proof **hardware-free**: it runs the **real** `pg-failover.sh` against a **fake
`kubectl`** that simulates the CNPG cluster + in-pod psql, and asserts the polarity —

- **POSITIVE** (all rows survive) → drill **GREEN** (exit 0) — the revert-to-green;
- **NEGATIVE CONTROL** (async last row lost after the kill) → drill **RED**, and the
  RED is specifically the **zero-committed-audit-loss** assertion (COUNT 6≠7 + last
  row MISSING + 1 `seq` gap; the surviving prefix's hash-chain stays valid — a
  faithful model of an async tail-loss);
- **NO-PROMOTION** (primary never changes) → **RED** (the promotion assertion bites);
- **SLOW-RTO** (write restored past the budget) → **RED** (the ≤ 60 s RTO bites).

This self-test is **blocking within the `kind-harness-ha` job** (it needs no
cluster) and is the recorded evidence the drill is a real gate, not green-at-setup.
It was **executed on the authoring host**: `bash ci/kind/selftest/pg-failover-bite.sh`
→ `0 failure(s)`, drill exit **3** (three zero-loss assertions) under the negative
control, exit **0** on the positive path.

### Gate posture — SIGNAL-ONLY (live), BLOCKING (static bite proof)

- The **live** failover drill runs inside the `HA=1` harness in the
  **`kind-harness-ha`** CI job, which stays **`continue-on-error` / absent from
  `all-gates`** (same posture as the rest of the HA live run). Promoting the
  G-REL/G-SCA HA drills to **blocking** is a deliberate later step (**W5/GA**), not
  W4-T3.
- The **static** negative-control bite proof (`pg-failover-bite.sh`) and the
  `validate-harness.sh` failover-drill invariants are **blocking within the job** —
  a silently weakened drill (RTO-from-detection, a dropped zero-loss assertion, a
  removed negative control, a SQLite path) fails there, with no cluster needed.
- **L1 caveat:** the **live** kill/promote/measure path has **not** run on the
  authoring host; it runs live only on the CI ubuntu runner. Do not claim a local
  live failover run.

### Reliability (the ADR-0048 §3 Prerequisite A) + L1 caveat

The HA bring-up is **deterministic** (pinned operator/CNI versions),
**idempotent** (server-side apply, re-appliable operators), **retried** where the
network is flaky (operator-manifest fetch/apply), and **readiness-gated** end to
end so a red aggregator means a real regression, not a "still coming up" race —
this reliability is the **explicit prerequisite** for W4-T2 promoting a live gate
to blocking. **L1:** kind **cannot** run on the W4-T1 authoring host (Windows, no
Docker/Linux kind), so the **live** HA bring-up is authored + **statically
validated** here and runs **live only on the CI ubuntu runner**; no local live
run happened. The **static** layers (the `validate-harness.sh` HA invariants +
`validate-ha-overlay.sh` render/count bite + the `infra` job's HA render →
kubeconform/kube-linter/conftest/Trivy) **gate hard**; the **live**
`kind-harness-ha` job stays **continue-on-error** / **non-blocking**. NOTE: W4-T2
targets the **P2** `kind-harness` job (the G-SEC mTLS + collector-egress live
assertions — see "Gate status" below), **not** this HA job; the reliable HA
substrate is the ADR-0048 §3 Prerequisite A *for that promotion*. That promotion is
**HELD** pending the ADR-0048 §4 executed bite (Prerequisite B, not yet run on any
runner per L1 — see "Gate status"), so the P2 `kind-harness` job is **also still
`continue-on-error` / absent from `all-gates`** for now. Promoting the
`kind-harness-ha` G-REL/G-SCA drills to blocking is a separate **deliberate later
step (W5/GA)**, not W4-T2.

## Gate status — SIGNAL-ONLY (promotion AUTHORED, HELD pending ADR-0048 §4 bite)

The P2 `kind-harness` live run (steps 1-6) is **not yet a blocking gate**. The
promotion to blocking for the two named P2 sub-items — **mTLS api/worker↔postgres
handshake + plaintext-refused** and **collector default-deny egress** — is
**authored** (the exact two edits ADR-0048 §2 names) but **deliberately held**
because the ADR-0048 §4 prerequisite has not been met:

- The live `kind-harness.sh` step (`id: harness`) is **still
  `continue-on-error: true`**, and the `kind-harness` job is **NOT** in the
  **`all-gates`** required-check aggregator's `needs` list (`.github/workflows/ci.yml`).
  So the two live assertions run for **SIGNAL only** — a live regression is surfaced
  as a warning in the job summary but does **not** block merge yet.
- **Why held (ADR-0048 §4, Prerequisite B — "non-negotiable"):** a promoted gate
  that has never been shown to bite is a **false-green blocking gate — worse than
  `continue-on-error`** (ADR-0048 Risks; Alternative 2 "Promote without the bite
  proof" is Rejected). Both live assertions must first be SHOWN to turn the gate
  **red** on a planted regression, then reverted to green, **on a CI ubuntu runner**.
  Per **P1-W4-LESSONS L1** kind cannot run on the authoring host (Windows, no
  Docker/Linux kind), so that observed red→green run has **not been executed on any
  runner yet** — it is authored, not proven (see "Prove-it-bites" below, which is a
  PROCEDURE to run, not a record of a run that happened).
- **Prerequisite A (satisfied):** the reliable enforcing-CNI W4-T1 HA topology is in
  place. **Prerequisite B (outstanding):** the executed bite. Only when a runner
  records both bites (with run URLs / a planted→red→reverted commit pair cited here)
  are the two promotion edits applied: drop the step's `continue-on-error` and add
  `kind-harness` to `all-gates` `needs`.
- The static `validate-harness.sh` step + the assertion-library self-tests +
  `extract_secret.py` tests stay **blocking within the job** regardless — the live
  run is signal-only **on top of** them.
- **Scope (when promoted):** only the two P2 sub-items above (ADR-0048 §1 / §6). No
  new security claim; no other live assertion joins `all-gates`.

### Why it can bite (assertions run, do not SKIP)

Both checks SKIP loudly (`exit 0`) if their control object is absent — a missing
control must never read as a pass. Under the harness apply they are **present**, so
the checks assert (they do not skip): the harness renders with
`--set mtls.postgres.enabled=true` (so `netops-db-client-tls` exists →
`mtls-postgres.sh` asserts) and `networkPolicy.collectorEgress` is default-on (so
`netops-allow-collector-mgmt-egress` exists → `collector-egress.sh` asserts).
Verified locally with `helm template netops … --set mtls.postgres.enabled=true
--set mtls.postgres.certManager.enabled=false` — both objects render.

### Prove-it-bites (ADR-0048 §4 — mandatory before promotion; NOT YET EXECUTED)

A promoted gate that does not bite is a **false-green blocking gate — worse than
`continue-on-error`**. ADR-0048 §4 therefore makes an EXECUTED plant→red→revert the
**precondition** for promoting the live run to blocking. **This bite has NOT been
run on any runner yet** (**L1:** kind cannot run on the authoring host — Windows, no
Docker/Linux kind — and no CI ubuntu-runner execution has been recorded). The table
below is the **procedure to execute** to earn the promotion, not a record of a run
that occurred. Until the observed red→green exists (with run URLs / a
planted→red→reverted commit pair recorded here), the live step stays
`continue-on-error` and `kind-harness` stays out of `all-gates` (see "Gate status"
above).

The two negative controls are **representative** and verified to work *in principle*
against the rendered manifests (the rendered `pg_hba` contains only
`hostssl … clientcert=verify-full` with no plaintext `host` line, so adding one makes
`assert_handshake_refused` fail; the broaden-not-delete collector plant genuinely
admits `1.1.1.1:53`), but "would work" is **not** "proven to bite" — ADR-0048 §4
demands the latter before blocking membership.

**Procedure (run on a CI ubuntu runner, then record the evidence here):**

| Control | Planted regression (makes it RED) | Assertion that fails | Revert (back to GREEN) |
|---|---|---|---|
| **mTLS handshake** | Add a plaintext `host all all 0.0.0.0/0 md5` line to the Postgres `pg_hba` (or set client `sslmode=disable` acceptance) so a plaintext connection is admitted | `assert_handshake_refused "plaintext (sslmode=disable) client"` in `ci/kind/assertions/checks/mtls-postgres.sh` — the plaintext probe now CONNECTS → refusal assertion fails → check non-zero → `kind-harness` job red (→ `all-gates` red once promoted) | Remove the plaintext `pg_hba` line (restore `hostssl … clientcert=verify-full` only) → plaintext refused again → green |
| **Collector egress** | Broaden the egress allow-list so the arbitrary external destination `1.1.1.1:53` is admitted while KEEPING the collector policy present (so the check asserts, not SKIPs): e.g. add `1.1.1.1/32` to `networkPolicy.collectorEgress.managementCidrs` and `53` to its ports, or add a live `kubectl patch`/extra allow-all-egress NetworkPolicy selecting the worker-labelled probe. (Deleting the whole floor via `--set networkPolicy.enabled=false` also removes `netops-allow-collector-mgmt-egress`, which makes the check SKIP rather than fail — use the broaden-not-delete plant so the deny assertion actually runs and goes RED.) | `assert_egress_blocked_retry "arbitrary external egress …"` in `ci/kind/assertions/checks/collector-egress.sh` — the external probe now REACHES `1.1.1.1:53` → deny assertion fails → check non-zero → `kind-harness` job red (→ `all-gates` red once promoted) | Remove the broadened allow (restore the narrow mgmt-subnet allow-list on top of the `netops-default-deny-all` floor) → external egress blocked again → green |

**Evidence (to be filled in when the bite is executed):** _not yet run — no CI
run URL / planted-regression commit pair exists._ When executed, record here the two
run URLs (or the planted→red→reverted commit SHAs) mirroring the `pg-integration`
`dd366bd` "proven to bite" precedent (`P2-RELEASE-READINESS.md` §1.1), THEN apply the
two promotion edits (drop `continue-on-error`; add `kind-harness` to `all-gates`
`needs`) and flip this section + "Gate status" to past tense.

### The HA live job stays NON-BLOCKING

Only the two G-SEC live assertions above are in scope for promotion (and that
promotion is itself HELD pending the §4 bite — see "Gate status"). The
`kind-harness-ha` job (the reduced-scale HA topology — CNPG + KEDA + Sentinel,
ADR-0047) is a **G-REL/G-SCA** reliability/scale path, not this G-SEC promotion; it
stays `continue-on-error` and **absent from `all-gates`** (see "HA topology" above
and the ci.yml DELIBERATE-OMISSION block). Promoting the HA drills to blocking is a
deliberate later step (W5/GA), not W4-T2.

## Failure modes

| Symptom | Meaning / action |
|---|---|
| `baseline egress failed BEFORE any deny policy` | The CNI is not routing pod egress at all (Calico not Ready / image pull failed). Check `kubectl -n kube-system get pods -l k8s-app=calico-node`. |
| `CNI SELF-TEST FAILED — default-deny did NOT block` | The CNI admits but does not enforce NetworkPolicy (e.g. `disableDefaultCNI` got flipped, kindnet present). This is the L1 false-green the harness exists to catch — fix the CNI install; do NOT weaken the self-test. |
| Assertion-runner: `check … produced NO output` | A check is a silent no-op — treated as a failure (a no-output check is a false-green). The check must emit at least its assertion results. |
| Leaked `netops-w4` cluster | Only possible if the process was `kill -9`'d past the trap; remove with `kind delete cluster --name netops-w4`. |
| HA: `<operator> install FAILED after N attempts` | The pinned CNPG/KEDA manifest could not be fetched/applied (network, or the pinned version was yanked). Check the `CNPG_VERSION`/`KEDA_VERSION` pins in `ci/kind/ha/install-operators.sh` against the current release feeds; the fetch is retried but a bad pin is a hard fail. |
| HA: `CNPG Cluster ... NOT ready ... readyInstances` | Fewer than 3 CNPG instances came Ready (replica scheduling / PVC / image pull). A primary-only cluster is NOT the HA quorum the failover drill needs — `wait-ha-ready.sh` correctly HARD-FAILS. Inspect `kubectl -n netops get cluster -o wide` + the CNPG pod events. |
| HA: `ScaledObject/... Ready NOT ready` | KEDA did not reconcile a `ScaledObject` (bad trigger, unresolved `TriggerAuthentication`, Sentinel not discovered). The per-queue autoscale substrate is not live; do NOT trust a queue-burst drill until this is Ready. |
| HA: `no KEDA ScaledObjects present` | The KEDA operator installed but the chart's ScaledObjects did not apply (KEDA CRDs not Established before apply, or `workerScaling.enabled` off in the overlay). Confirm the overlay + the CRD-Established wait in `install-operators.sh`. |
| Failover drill: `SKIP: CNPG Cluster … absent` | The drill ran on a **non-HA** harness (no `HA=1`, so no CNPG operator/Cluster). Expected on the P2 path — the failover drill only asserts under `HA=1`. Not a failure. |
| Failover drill: `committed-audit LOSS … zero-loss VIOLATED` / `seq GAP` | A committed audit row did **not** survive promotion — a real G-REL §316 durability regression (or the negative control is active). Check the audit write path is quorum-sync (`SET LOCAL synchronous_commit=remote_apply`, ADR-0042 §2) and the CNPG `synchronous`/`failoverQuorum` config; confirm `PG_FAILOVER_DRILL_NEGATIVE_CONTROL` is **not** set on a real run. |
| Failover drill: `write service NOT restored within …` or `RTO … EXCEEDS budget` | No automated promotion, or promotion slower than the 60 s RTO. Inspect `kubectl -n netops get cluster -o wide` + the CNPG operator events; a stuck promotion means the HA quorum is not healthy (re-check `wait-ha-ready.sh` passed). |
| `pg-failover bite proof found N violation(s)` | `pg-failover-bite.sh` (no cluster) found the drill no longer bites correctly — e.g. the negative control stopped turning the drill red, or the happy path went false-red. The drill is not a real gate until this is green; do **not** trust a live green until the bite proof passes. |
