# Runbook — Ephemeral in-CI kind cluster harness (W4-T3)

> Operator/developer procedure for the ADR-0041 §2/§3 + ADR-0039 §6 kind harness: how it brings up a throwaway cluster with an **enforcing CNI**, proves the CNI actually enforces NetworkPolicy (the **CNI self-test bite**), applies the chart, and runs the assertion-runner that **W4-T4 (mTLS handshake)** and **W4-T5 (collector egress deny)** plug their assertions into. Records that the P2 live kind job's promotion to a **blocking gate** for the two named G-SEC sub-items (mTLS handshake + collector egress deny) is **REJECTED** (ADR-0048, 2026-07-03, audit-W2 T7) — not pursued: the live step stays `continue-on-error`, the job is now **opt-in** (label `ci-kind` / manual dispatch, silenced on ordinary PRs), and the two controls stay enforced at runtime + protected by BLOCKING static gates (see "Gate status" below). The `kind-harness-ha` HA live job likewise stays non-blocking. Cheap-scope only — handshake + deny; HA/scale/soak are P3-Platform.

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
| CI job (P2) | `.github/workflows/ci.yml` job `kind-harness` (**signal-only, OPT-IN** — promotion **REJECTED** per ADR-0048; runs only on `workflow_dispatch` or the `ci-kind` label; step stays `continue-on-error`, NOT in `all-gates` needs; see "Gate status" below) |
| CI job (HA, P3 W4-T1) | `.github/workflows/ci.yml` job `kind-harness-ha` (**non-blocking live** — see "HA topology" + "Gate status") |
| Cluster name | `netops-w4` (`CLUSTER_NAME` override) |
| HA operator installer | `ci/kind/ha/install-operators.sh` (CloudNativePG `1.29.1` + KEDA `2.16.1`, pinned; `CNPG_VERSION`/`KEDA_VERSION` override) |
| HA readiness gate | `ci/kind/ha/wait-ha-ready.sh` (a half-up topology must NOT read ready — L5) |
| HA overlay validator | `ci/kind/ha/validate-ha-overlay.sh` (static render + reduced-scale count bite) |
| Reduced-scale HA overlay | `deploy/kubernetes/netops/values-kind-ha.yaml` (`HA_VALUES` override) |
| Postgres failover drill (P3 W4-T3) | `ci/kind/assertions/checks/pg-failover.sh` + `pg-failover-drill-probe.yaml` (G-REL §316 — runs on the HA path via the assertion-runner) |
| Failover drill bite proof (P3 W4-T3) | `ci/kind/selftest/pg-failover-bite.sh` (hardware-free negative-control plant→red→revert; runs in `kind-harness-ha`, no cluster) |
| Worker-kill idempotency drill (P3 W4-T5) | `ci/kind/assertions/checks/worker-kill-idempotency.sh` + `worker_idem_probe.py` (G-REL §319/§320 — runs on the HA path via the assertion-runner; asserts on real PG) |
| Worker-kill drill bite proof (P3 W4-T5) | `ci/kind/selftest/worker-kill-idempotency-bite.sh` (hardware-free negative-control plant→red→revert; runs in `kind-harness-ha`, no cluster) |
| Queue-burst + API load + PgBouncer drill (P3 W4-T6) | `ci/kind/assertions/checks/queue-burst-load.sh` + `queue-burst-load-drill-probe.yaml` (G-SCA §326–§330 — runs on the HA path via the assertion-runner) |
| Queue-burst/load drill bite proof (P3 W4-T6) | `ci/kind/selftest/queue-burst-load-bite.sh` (hardware-free negative-control plant→red→revert; runs in `kind-harness-ha`, no cluster) |
| Compressed-soak drill (P3 W4-T7) | `ci/kind/assertions/checks/compressed-soak.sh` + `compressed-soak-drill-probe.yaml` (G-REL §315 compressed — runs on the HA path via the assertion-runner) |
| Compressed-soak drill bite proof (P3 W4-T7) | `ci/kind/selftest/compressed-soak-bite.sh` (hardware-free — REAL `promtool test rules` over the W3-T2/W3-T3 rules + fake-kubectl drill-flow polarity; runs in `kind-harness-ha`, no cluster) |
| Compressed-soak SLO-held promtool fixture (P3 W4-T7) | `deploy/observability/slo-compressed-soak.test.yaml` (healthy window silent + injected-regression firing case over the real recording/alert rules) |
| N-2 → N upgrade rehearsal drill (P3 W4-T8) | `ci/kind/assertions/checks/n2-upgrade-rehearsal.sh` + `n2-upgrade-rehearsal-drill-probe.yaml` (G-MNT §346 — runs on the HA path via the assertion-runner) |
| Upgrade rehearsal drill bite proof (P3 W4-T8) | `ci/kind/selftest/n2-upgrade-rehearsal-bite.sh` (hardware-free fake-kubectl drill-flow polarity: additive-expand GREEN, contract-too-early + force-unavail RED; runs in `drill-bite-proofs` + `kind-harness-ha`, no cluster) |
| Pre-upgrade Alembic migrate Job (P3 W4-T8) | `deploy/kubernetes/netops/templates/db-migrate-job.yaml` (`migrationJob.preUpgrade`, Helm `pre-install,pre-upgrade` hook weight −5; default OFF, enabled in `values-kind-ha.yaml`) |

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
| primary kill → promote ≤ 60 s; every committed audit row survives, hash-chain-valid, no `seq` gap | **async / non-quorum commit** on the audit path (`PG_FAILOVER_DRILL_NEGATIVE_CONTROL=1` → the last row commits `synchronous_commit=off`) with a **deterministically engineered loss window** → a just-committed audit row is **lost** on the promoted primary → the zero-loss COUNT + last-row + seq-gap assertions go **RED** |

**Why the live loss is DETERMINISTIC, not timing-dependent.** At this reduced kind
scale the async WAL for a tiny row can stream to a standby in **milliseconds**, and
CNPG promotes a standby that already holds the quorum-acked WAL — so a *naive*
async-commit-then-kill negative control could be **FALSE-GREEN** (the row survives,
zero-loss passes) whenever streaming happened to win the race. To close that gap the
negative control **engineers the loss window**: immediately **before** the async
commit it **terminates the walsender backends** on the current primary
(`pg_terminate_backend(pid) FROM pg_stat_replication`), severing streaming to every
standby, then force-kills with **no intervening sleep**. With no walsender attached,
the `synchronous_commit=off` row is acked by the primary without its WAL reaching
**any** standby, and the primary is destroyed before a standby can re-attach and
re-stream that segment — so the row is **provably absent** on the promoted primary.
The bite is engineered, not lucky. (The positive path is untouched: it commits
quorum-sync `remote_apply`, which by definition waits for a replica.)

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
- **Live negative-control caveat (W5/GA promotion path).** The ADR-0047 §2
  proof-it-bites for this drill is the **hardware-free self-test**
  (`pg-failover-bite.sh`, blocking within `kind-harness-ha`); the **live** run only
  **corroborates** it. The live negative control now uses an **engineered**
  deterministic loss window (walsender-terminate), so a green live negative-control
  run is a real bite rather than a timing coincidence — **but that engineered window
  has not itself been exercised on the CI CNPG topology** (L1). Therefore, before any
  **W5/GA promotion of this drill to blocking**, the live negative control **MUST be
  re-verified on the CI runner** (plant → observe RED → revert → GREEN on the actual
  cluster). Until that live re-verification, treat a green live negative-control run
  as **advisory corroboration**, not standalone proof for blocking promotion. This is
  a named prerequisite on the ADR-0047 §4 promotion path.

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

## Worker-kill idempotency + Celery ≥99% drill (P3 W4-T5, G-REL §319/§320) — the idempotency drill on this HA topology

The same HA topology is the substrate for the **worker-kill idempotency drill**
(`ci/kind/assertions/checks/worker-kill-idempotency.sh`). It plugs into the same
assertion-runner, so on the **HA path** (`HA=1 ci/kind/kind-harness.sh`) it runs
automatically after the HA-readiness gate — no separate invocation.

### §11 criterion + target (ADR-0008 §5, ADR-0043 §6, ADR-0020, ADR-0047 §3/§5)

| Gate / line | Target (reduced-scale run) |
|---|---|
| **G-REL §319** | a worker node **killed mid-run** → each side-effecting job (discovery/config write, CR-gated config op, docs/backup gen) **completes via retry with NO duplicate side effect** — a **single** DB write, a **single** ChangeRequest execution, a **single** audit row (the W2-T4 idempotency under `acks_late` + `reject_on_worker_lost`, ADR-0008 §5). The CR **four-eyes** gate (ADR-0020) is **not bypassed or double-executed** on the retry. Asserted on **real PG** (the kind CNPG cluster), never SQLite (ADR-0047 §5). |
| **G-REL §320** | **Celery success ≥ 99%** after retries over the window. |

### What the drill does

1. **Precondition / SKIP.** If no worker pod is present (a non-HA run) the drill
   **SKIPs loudly** (`exit 0`) — a missing worker tier is never a false-green pass.
2. **Seed.** Runs `worker_idem_probe.py seed` on a worker pod: a fixed drill fixture
   (1 device + 2 drill users, keyed by fixed ids) in **real Postgres**.
3. **Kill.** `kubectl delete pod <worker> --force --grace-period=0` — a real
   node-loss trigger; with `acks_late` + `reject_on_worker_lost` (ADR-0008 §5) an
   in-flight task on the killed worker is **redelivered**, not lost.
4. **Drive the redelivery + assert** on a **surviving** worker (or the recreated
   replacement on a single-worker overlay), via the real W2-T4 code path
   (`config._persist` / `ChangeRequestService` / `nightly_backup`):
   - **config capture double-delivery** → exactly **1** `config_snapshots` row + **1**
     `config.snapshot_captured` audit row (content-addressed dedup + the W2-T4
     audit-once fix);
   - **CR execution retry** → **1** `approved_to_executing` transition + **1**
     approval, the CR stays `executing`, the self-approve is still refused
     (four-eyes intact, ADR-0020) — the retry is an idempotent `ConflictError` no-op;
   - **nightly_backup double-delivery** (same `run_id`) → **1** started + **1**
     finished audit row + **1** fan-out wave (`config_backup_runs` `ON CONFLICT DO
     NOTHING` guard, ADR-0043 §6);
   - **success rate** → `ATTEMPTS` redeliveries (default **40**), each must complete
     exactly-once → **success ≥ 99%** (G-REL §320).

### Reduced scale (STATED) + named ceiling (ADR-0047 §1/§4)

The drill proves the **worker-kill → complete-via-retry → exactly-once mechanism**
bites at reduced scale: a **1-device / 2-user** fixture and a **compressed
success-rate window** (40 redeliveries), success floor **99%**. It does **not**
certify a scale point. The **certified-scale soak success** over a **30-day
calendar window** (G-REL §315/§320) stays **deferred-accepted → GA** with the
ADR-0047 §4 written promotion path (a sized cluster; run the calendar soak; assert
≥ 99% over 30 days) — **never claimed** from this run.

### Real PG, not SQLite (ADR-0047 §5)

The exactly-once + four-eyes checks are meaningless on SQLite (single-writer, no
true isolation / unique-constraint concurrency). They run against the kind CNPG
cluster (real Postgres); the in-pod `worker_idem_probe.py` **HARD-FAILS** if
`database_url` is not a `postgresql` URL — there is no SQLite path. The same
exactly-once property is also asserted on real PG in
`backend/tests/pg/test_worker_idempotency_pg.py` behind the **blocking**
`pg-integration` job.

### Negative control — PROVEN to bite (ADR-0047 §2)

| Positive assertion | Planted negative control (turns it RED) |
|---|---|
| worker kill → each redelivery completes exactly-once (1 snapshot / 1 audit / 1 CR transition), success ≥ 99% | **idempotency guard disabled** (`WORKER_KILL_DRILL_NEGATIVE_CONTROL=1` → the probe bypasses the content-addressed dedup / state-machine guard) → the redelivered capture **double-writes** (2 snapshots / 2 audits), the CR **double-executes** (2 transitions), and the success rate **collapses** below the floor → the exactly-once + ≥99% assertions go **RED** |

**How the bite is proven WITHOUT a cluster (L1).** The live drill runs only on the
kind cluster (Windows authoring host has no Docker/Linux kind).
`ci/kind/selftest/worker-kill-idempotency-bite.sh` earns the ADR-0047 §2
plant→red→revert proof **hardware-free**: it runs the **real**
`worker-kill-idempotency.sh` against a **fake `kubectl`** that simulates the worker
pods + the in-pod probe, and asserts the polarity —

- **POSITIVE** (a worker is killed; each redelivery exactly-once, success ≥ 99%) →
  drill **GREEN** (exit 0) — the revert-to-green;
- **NEGATIVE CONTROL** (guard off → double-write, success collapse) → drill **RED**,
  and the RED is specifically the **exactly-once / success-rate** assertion
  (`DUPLICATED a side effect` / `success rate … <` / `G-REL §319/§320 VIOLATED`);
- **NO-KILL + guard-off** → **RED** (the exactly-once assertion catches the
  double-write regardless of whether the kill succeeded).

This self-test is **blocking within the `kind-harness-ha` job** (it needs no
cluster) and is the recorded evidence the drill is a real gate, not green-at-setup.
It was **executed on the authoring host**: `bash
ci/kind/selftest/worker-kill-idempotency-bite.sh` → `0 failure(s)`, drill exit **4**
(four exactly-once/rate assertions) under the negative control, exit **0** on the
positive path.

### Gate posture — SIGNAL-ONLY (live), BLOCKING (static bite proof)

- The **live** worker-kill drill runs inside the `HA=1` harness in the
  **`kind-harness-ha`** CI job, which stays **`continue-on-error` / absent from
  `all-gates`** (same posture as the rest of the HA live run). Promoting this
  G-REL drill to **blocking** is a deliberate later step (**W5/GA**), not W4-T5.
- The **static** negative-control bite proof (`worker-kill-idempotency-bite.sh`),
  the `validate-harness.sh` worker-kill-drill invariants, **and** the real-PG
  `pg-integration` `test_worker_idempotency_pg.py` are **blocking** — a silently
  weakened drill (no kill, a dropped exactly-once assertion, a bypassed four-eyes
  gate, a SQLite path, a removed negative control) fails there, no cluster needed.
- **L1 caveat:** the **live** kill/redeliver/measure path has **not** run on the
  authoring host; it runs live only on the CI ubuntu runner. Do not claim a local
  live worker-kill run. Before any W5/GA promotion of this drill to blocking, the
  live negative control **MUST be re-verified on the CI runner** (plant → RED →
  revert → GREEN on the actual cluster) — a named prerequisite on the ADR-0047 §4
  promotion path.

## Queue-burst + API load + PgBouncer budget drill (P3 W4-T6, G-SCA §326–§330)

The HA topology is also the substrate for the **G-SCA scale drill**
(`ci/kind/assertions/checks/queue-burst-load.sh`). It plugs into the same
assertion-runner (auto-discovered under `checks/`) and asserts three §11 G-SCA
mechanisms in one drill.

### §11 criteria + targets (ADR-0043 §2/§3, ADR-0042 §4, ADR-0047 §3)

| Criterion | Target (reduced-scale run) |
|---|---|
| Queue-burst isolation (§329) | 10× normal `discovery` depth → KEDA **scale-out** then **scale-in** within the burst-drain SLO; `config`/`docs`/`packet_*` siblings **not starved** (per-queue isolation) |
| API load p95 + replica delta (§327) | reduced-concurrency load holds **p95** under the reduced-scale budget with the api at its HA floor (2), a **1→2-replica improvement** shown, **zero 5xx** |
| PgBouncer budget (§330) | concurrent client connections multiplexed through the transaction-mode Pooler with **no connection-exhaustion error** |

### What the drill does

1. **Precondition / SKIP.** If no KEDA `ScaledObject` (`netops-worker-discovery`) is
   present (a non-HA run) the drill **SKIPs loudly** and asserts nothing — never a
   false-green pass.
2. **Burst.** `RPUSH`es `QUEUE_BURST_ITEMS` (default 50 = 10× the `listLength=5`
   target) placeholder tasks into the **real** Redis list keyed `discovery` — the
   same key the KEDA `redis-sentinel` scaler reads `LLEN` on, so KEDA's own signal
   fires. The Redis password is fed over **stdin** (never argv).
3. **Assert scale-OUT (the replica count ACTUALLY changed).** Polls the discovery
   worker Deployment's `.spec.replicas` until it **exceeds** its baseline. A burst
   that never moves the replica count is a **false-green** (the spec's named risk) —
   this assertion is what makes the scale-out real.
4. **Assert per-queue isolation.** Seeds a small sibling backlog and asserts each
   sibling Deployment's replicas did **not** collapse below baseline (its per-queue
   budget was not stolen) — the structural one-ScaledObject-per-Deployment isolation
   (ADR-0043 §3).
5. **Assert scale-IN.** Drains the burst (`DEL discovery`) and asserts the discovery
   Deployment scales back toward its floor within the scale-in window (KEDA
   `cooldownPeriod`) — the burst-drain SLO half of §329.
6. **API load.** Brings up a hardened probe pod and runs a reduced-concurrency HTTP
   load (`API_LOAD_VUS` VUs / `API_LOAD_REQUESTS` reqs) against the api Service via
   **bash `/dev/tcp`** (no k6/locust/curl dependency — the pgvector probe image ships
   bash + psql; each request is a raw HTTP/1.1 GET timed with `EPOCHREALTIME`) at **1
   replica** and **2 replicas**, asserting **p95 ≤ budget**, a **1→2 improvement**,
   and **zero 5xx**.
7. **PgBouncer budget.** Opens `POOL_PROBE_CONNS` concurrent psql connections through
   the transaction-mode Pooler rw Service and asserts **no connection-exhaustion
   error** (§330, ADR-0042 §4). The DB password is fed over **stdin** (never argv).

### Reduced scale (STATED) + named ceiling (ADR-0047 §1/§4)

The drill proves the **queue-burst scale-out/in + per-queue isolation + p95/1→2 +
PgBouncer-budget mechanisms** bite at reduced scale: **burst = 50 pending
`discovery` tasks** (10× `listLength`), **api floor 2 / ceiling 4**, **~20 VUs /
400 reqs**, **~40 concurrent pooler connections**. It does **not** certify a scale
point. The certified-scale G-SCA ceilings — **500-device discovery ≤ 60 min** with
autoscale (§326), **100 concurrent users at p95 < 300 ms with 2→4-replica
linearity** (§327), **5,000-device / 100k-interface projection** (§328) — stay
**deferred-accepted → GA / customer cluster** with the ADR-0047 §4 written promotion
path; they are **never claimed** from this run.

### Negative control — PROVEN to bite (ADR-0047 §2)

| Positive assertion | Planted negative control (turns it RED) |
|---|---|
| 10× `discovery` burst → scale-out then scale-in; siblings not starved; p95 held + 1→2 improvement + zero 5xx; PgBouncer no exhaustion | `QUEUE_BURST_DRILL_NEGATIVE_CONTROL=1` emulates a **shared/misconfigured scaler that STARVES a sibling** (its Deployment is scaled to 0 — the budget-stolen starvation a shared autoscaler produces) **and** overruns the **PgBouncer connection budget** (connection exhaustion + p95 breach) → the per-queue-isolation + §330 + §327 assertions go **RED** |

The negative control emulates the two failures the ADRs forbid **without re-tuning
the real chart's ScaledObjects/Pooler** (scope: one drill, no unrelated re-tuning) —
it drives the observable starvation + exhaustion the assertions must catch.

**How the bite is proven WITHOUT a cluster (L1).** The live drill runs only on the
kind HA cluster, which cannot run on the authoring host (Windows, no Docker/Linux
kind). `ci/kind/selftest/queue-burst-load-bite.sh` earns the ADR-0047 §2
plant→red→revert proof **hardware-free**: it runs the **real** `queue-burst-load.sh`
against a **fake `kubectl`** that simulates the ScaledObjects + Deployment replica
counts + Redis `LLEN` + the in-pod loadgen / pool probe, and asserts the polarity —

- **POSITIVE** (scale-out/in, no starvation, p95 held + 1→2, no exhaustion) → drill
  **GREEN** (exit 0) — the revert-to-green;
- **NEGATIVE CONTROL** (sibling starved + PgBouncer budget overrun) → drill **RED**,
  and the RED is specifically the isolation / connection-budget assertion;
- **NO-SCALE-OUT** (the burst never moves the replica count) → **RED** (the
  "replica count actually changed" assertion bites — the spec's false-green risk).

This self-test is **blocking within the `kind-harness-ha` job** (it needs no cluster)
and is the recorded evidence the drill is a real gate, not green-at-setup. It was
**executed on the authoring host**: `bash ci/kind/selftest/queue-burst-load-bite.sh`
→ `0 failure(s)`; drill exit **4** under the negative control (isolation + §330 +
§327 assertions), exit **1** on no-scale-out, exit **0** on the positive path. The
static `validate-harness.sh` W4-T6 invariants were likewise shown to bite (a
neutered scale-out assertion → RED; reverted → GREEN).

### Gate posture — SIGNAL-ONLY (live), BLOCKING (static bite proof)

- The **live** queue-burst/load drill runs inside the `HA=1` harness in the
  **`kind-harness-ha`** CI job, which stays **`continue-on-error` / absent from
  `all-gates`**. Promoting the G-SCA HA drill to **blocking** is a deliberate later
  step (**W5/GA**), not W4-T6.
- The **static** negative-control bite proof (`queue-burst-load-bite.sh`) and the
  `validate-harness.sh` W4-T6 invariants are **blocking within the job** — a silently
  weakened drill (a burst that never scales out, a dropped isolation/§330/§327
  assertion, a removed negative control, a SQLite path) fails there, no cluster
  needed.
- **L1 caveat:** the **live** burst/scale/load/pool path has **not** run on the
  authoring host; it runs live only on the CI ubuntu runner. Do not claim a local
  live queue-burst/load run. Before any W5/GA promotion of this drill to blocking, the
  live negative control **MUST be re-verified on the CI runner** (plant → RED →
  revert → GREEN on the actual cluster) — a named prerequisite on the ADR-0047 §4
  promotion path.

## Compressed-soak drill (P3 W4-T7, G-REL §315 compressed) — §6 SLOs hold over the compressed window

The compressed-soak drill (`ci/kind/assertions/checks/compressed-soak.sh`) is
auto-discovered by the assertion-runner and runs on the `HA=1` path. It proves the
**§6 SLOs are measurable and HELD over a sustained-but-compressed run** and that no
resource leaks over that run — the compressed-soak MECHANISM (ADR-0047 §1/§2/§3).

### §11 criterion + target (ADR-0046 §1/§2/§6, ADR-0047 §3)

- **G-REL §315 (compressed):** drive STEADY mixed synthetic load over a compressed
  window and assert the §6 SLO recording rules (W3-T2) stay **within budget** so **no
  multi-window burn-rate alert (W3-T3) fires**, and that there is **no slow resource
  regression** (connections / memory / queue depth stay bounded — a trend → fail).

### What the drill does

1. Records a **START-of-window resource baseline** — PgBouncer server-connection
   count (via `pg_stat_activity` through the Pooler rw Service), the discovery worker
   RSS (cgroup `memory.current`), and each soak queue's `LLEN`.
2. Drives `COMPRESSED_SOAK_WINDOW_S` (default **600 s / 10 min**) of **steady mixed
   load** — a reduced-concurrency HTTP read load against the api Service (bash
   `/dev/tcp`, no k6/locust) **plus** a steady discovery/config/docs queue-job
   trickle — sampling the §6 SLIs every `COMPRESSED_SOAK_SAMPLE_INTERVAL_S`
   (default **30 s**), so the window carries **many** samples.
3. Each sample computes the **same SLIs the W3-T2 recording rules derive**: the
   non-5xx availability error ratio, the fraction of reads exceeding the 300 ms p95
   boundary, and (from a `/metrics` scrape) the discovery success ratio. The drill
   tracks the **worst** SLI over the window and asserts each stayed **within the
   fast-burn budget** (the W3-T3 14.4× thresholds) — i.e. **no burn-rate alert would
   fire**. The SLO is HELD only if **every** sample stayed in budget.
4. Records an **END-of-window resource sample** and asserts each resource stayed
   **BOUNDED** (delta ≤ tolerance) — a monotone rise is a leak that would surface
   over calendar time → **fail**.

### Reduced scale (STATED) + named ceiling (ADR-0047 §1/§4)

- **Reduced scale ran at:** a **~10-minute compressed window** (default; tunable),
  ~tens of virtual users + a steady per-queue trickle, on the W4-T1 reduced-scale HA
  cluster. This proves the SLO-held + no-slow-regression **MECHANISM**, not the
  calendar SLA.
- **Named-deferred → GA:** the **30-day CALENDAR soak meeting all §6 SLOs** (G-REL
  §315) is **deferred-accepted → GA / customer cluster**, **never claimed here**.
  **Promotion path (ADR-0047 §4):** a 30-day staging window on a sized cluster; run
  the calendar soak, assert §6 SLOs.

### Negative control — PROVEN to bite (ADR-0047 §2)

`COMPRESSED_SOAK_DRILL_NEGATIVE_CONTROL=1` injects an **SLO regression** (an
error-rate + latency perturbation on the synthetic load → the availability + latency
SLIs breach their budget over the window → a burn-rate breach) **and** a **monotone
resource leak** (connection / RSS / queue-depth trend), so the SLO-held +
bounded-trend assertions go **RED**. The bite is earned **hardware-free** in two
layers by `ci/kind/selftest/compressed-soak-bite.sh`:

1. **The load-bearing layer runs a REAL `promtool test rules`** over the ACTUAL
   W3-T2 recording rules + W3-T3 burn-rate alerts
   (`deploy/observability/slo-compressed-soak.test.yaml`): a HEALTHY
   compressed-soak-shaped window fires **NO** alert (SLOs held), and the injected
   error-rate + latency perturbation **DOES** fire the burn-rate alert (RED). This
   proves the soak's core assertion ("no burn-rate alert fires over the window")
   bites against the same rules Prometheus loads.
2. It runs the real `compressed-soak.sh` against a fake `kubectl` and asserts the
   polarity — GREEN when the SLIs stay in budget + resources bounded, RED under the
   negative control.

Executed on the authoring host: **0 failure(s)** — promtool SUCCESS (healthy silent
+ injected regression fires); the drill exits **0** on the positive path and **8**
under the negative control (the SLO-held + trend assertions bite). The bite proof
itself has a **negative control on the bite**: flipping the promtool fixture's
firing case to expect no alert makes `promtool test rules` FAIL with `exp:[] got:[…
NetopsApiAvailabilityFastBurn …]` — confirming the fire is genuinely asserted.

### Gate posture — SIGNAL-ONLY (live), BLOCKING (static bite proof)

- The **live** soak drill runs inside the `HA=1` harness in the **`kind-harness-ha`**
  CI job, which stays **`continue-on-error` / absent from `all-gates`**. Promoting
  the G-REL soak drill to **blocking** is a deliberate later step (**W5/GA**), not
  W4-T7.
- The **static** bite proof (`compressed-soak-bite.sh`, incl. the real `promtool`
  run) and the `validate-harness.sh` W4-T7 invariants are **blocking within the job**
  — a silently weakened soak (a dropped SLO-held budget check, a removed
  bounded-trend guard, a removed negative control, a SQLite path) fails there, no
  cluster needed.
- **L1 caveat:** the **live** steady-load + SLI-sampling path has **not** run on the
  authoring host; it runs live only on the CI ubuntu runner. Do not claim a local
  live soak run. Before any W5/GA promotion of this drill to blocking, the live
  negative control **MUST be re-verified on the CI runner** (plant → RED → revert →
  GREEN on the actual cluster) — a named prerequisite on the ADR-0047 §4 promotion
  path.

## N-2 → N upgrade rehearsal drill (P3 W4-T8, G-MNT §346) — the rolling-upgrade drill on this HA topology

The upgrade rehearsal (`ci/kind/assertions/checks/n2-upgrade-rehearsal.sh`) rehearses
the **N-2 → N rolling upgrade** on the reduced-scale HA kind cluster: seed an N-2-shaped
dataset, run the Alembic **expand** migration (`alembic upgrade head` + an additive
`ADD COLUMN`) as the pre-upgrade step, roll the workers (warm shutdown) then the api
(holding the ≥2-ready floor), then the post-upgrade Neo4j re-projection — asserting the
**rolling-upgrade-without-downtime** property. It plugs into the HA assertion-runner
(`HA=1` only; loud SKIP on the P2 tier) and drives every DB assertion through psql on the
CNPG rw Service (real PG only; the password is fed over stdin, never argv — L3/L5).

### What the drill asserts

1. **N-1/N-2 reader compat** — an N-1 pod (reads only `n1_col`) still works against the
   migrated schema. The expand is **additive** (`ADD COLUMN`), so it never breaks a
   concurrent old reader. The **contract** (dropping the now-unused column) ships a
   release LATER, after the prior version leaves support (PRODUCTION.md §10 — NAMED
   deferred, not run here).
2. **No committed-data loss** — the seeded rows all survive the migration + roll.
3. **Audit spine intact** — `audit_log` count + `max(seq)` do not regress across the
   migration (ADR-0038 §3).
4. **No downtime** — the api never drops below its ≥2-ready floor through the roll.

### The Helm pre-upgrade migrate Job (the automated rolling order)

`deploy/kubernetes/netops/templates/db-migrate-job.yaml` runs the expand
(`alembic upgrade head`) as a `pre-install,pre-upgrade` hook (weight −5) so the schema
reaches release N **before** Helm rolls the workloads; the existing
`neo4j-auto-rebuild` post-upgrade hook re-projects the topology after. Full rolling
order: **migrate (pre-upgrade) → workers → api → Neo4j rebuild (post-upgrade)**. The Job
is `migrationJob.preUpgrade.enabled` (default **OFF** — existing operators keep the
documented manual `alembic upgrade head` step); it is enabled in `values-kind-ha.yaml`
so the rehearsal exercises it. Making it the platform default is a **GA decision**
(named, not silent).

### Negative controls — PROVEN to bite (ADR-0047 §2)

Two planted regressions, both proven hardware-free by
`ci/kind/selftest/n2-upgrade-rehearsal-bite.sh` (the **real** drill against a **fake
`kubectl`**):

1. **Contract-too-early** (`N2_UPGRADE_DRILL_NEGATIVE_CONTROL=1`) — the migration
   `DROP COLUMN n1_col` (a column an N-1 pod still reads) instead of the additive expand
   → the N-1 reader breaks → **RED** (the exact §10 expand/contract breach).
2. **Force-unavailability** (`N2_UPGRADE_DRILL_FORCE_API_UNAVAIL=1`) — the api is driven
   below its ≥2-ready floor during the roll → the no-downtime assertion → **RED**.

The bite was **executed on the authoring host**: `bash
ci/kind/selftest/n2-upgrade-rehearsal-bite.sh` → `0 failure(s)` (POSITIVE additive-expand
GREEN; both negative controls turn the drill RED via the attributable assertion). A
rehearsal whose "no downtime / no data loss" would read green regardless is not a gate
(P1-W4 false-green).

### Reduced scale (STATED) + named ceiling (ADR-0047 §1/§4)

Runs on the W4-T1 reduced-scale cluster (CNPG 1+2, api floor 2) with a small fixed
seeded dataset — it proves the expand → rolling-order → rebuild → no-loss **mechanism**
bites. The **prod-shaped seeded dataset** (a full-inventory upgrade) and the **contract
migration timing** stay deferred-accepted → GA with the ADR-0047 §4 / PRODUCTION.md §10
written promotion path — never claimed from this run.

### Gate posture — SIGNAL-ONLY (live), BLOCKING (static bite proof)

Same posture as the sibling drills: the **static** bite proof
(`n2-upgrade-rehearsal-bite.sh`) runs **blocking** in `drill-bite-proofs` (and the static
section of `kind-harness-ha`), cluster-free; the **live** in-cluster run is opt-in /
`continue-on-error` (ADR-0048 Rejected — not promoted). Before any GA promotion of the
live run to blocking, the live negative control MUST be re-verified on the CI runner.

## Gate status — SIGNAL-ONLY, OPT-IN (promotion REJECTED — ADR-0048)

> **REJECTED (2026-07-03, audit-W2 T7).** The ADR-0048 promotion of the P2
> `kind-harness` live run to a blocking gate will **not** be pursued. The live
> `kind-harness` / `kind-harness-ha` jobs are now **opt-in** — they run only on a
> manual `workflow_dispatch` or when a PR carries the **`ci-kind`** label, and are
> silenced on ordinary PRs. The live `kind-harness.sh` step stays `continue-on-error`
> and out of `all-gates` **permanently, by decision**.
>
> **Why:** getting the live run green requires booting a slice of the whole hardened
> platform in a bare kind cluster (the platform's own images are not loaded →
> `ImagePullBackOff`; the hardened Postgres StatefulSet never reaches Ready). The two
> controls it would gate (mTLS plaintext-refusal, collector default-deny egress) are
> ALREADY enforced at runtime AND protected by **blocking** static/manifest gates on
> every PR — the `infra` `conftest pg_hba weak-hostssl` bite, render-twice L4, the
> CR-schema guard, and the five `drill-bite-proofs` (in `all-gates`). The live
> promotion added only marginal "the CNI physically enforces" coverage — not worth a
> permanent flaky ~20-min blocking gate on the merge path. Security posture is
> unchanged. See ADR-0048 "Rejection".
>
> The "AUTHORED but HELD" description below is retained as historical context.

## Gate status (historical) — promotion AUTHORED, HELD pending ADR-0048 §4 bite

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
- The static `validate-harness.sh` step + the assertion-library self-tests stay
  **blocking within the job** regardless. The shared rendered-Secret extractor's
  bite proofs run separately in the normal blocking backend suite
  (`test_render_twice_helpers.py`) — the live run is signal-only **on top of**
  those static layers.
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

> **Audit-W2 T7 promotion attempt — ROLLED BACK (2026-07-02).** A Wave-2 commit
> promoted `kind-harness` AND `kind-harness-ha` to blocking without the executed
> bite (the exact ADR-0048 Rejected Alternative 2), asserting evidence in a
> `W2-GATE-PROMOTION-EVIDENCE.md` file that was never created. Review caught it and
> the promotion was reverted to the held state described above. The attempt did
> yield two real live-rot repairs, which are KEPT: the KEDA release-manifest
> Deployment name (`keda-metrics-apiserver`) in `ci/kind/ha/install-operators.sh`,
> and dropping the forced `-n` namespace override on the chart apply in
> `ci/kind/kind-harness.sh`. The live runs were still RED at rollback time (e.g. the
> HA apply rejects the CNPG `Cluster` on an unknown `spec.postgresql.runAsNonRoot`
> field) — the harness must first run GREEN on a CI runner, and only then can the
> plant→red→revert→green procedure below be executed to earn the promotion.
>
> **Recovery — runAsNonRoot rot FIXED + S1 guard added; harness STILL NOT green (PR #94; NOT
> a promotion).** The `spec.postgresql.runAsNonRoot` rot was root-caused (an invalid CNPG
> field the live apply rejects; it was ALSO *required* by a `hardening.rego` rule + mirrored
> in 4 `cnpg_*` fixtures — all removed), and a static **CR-schema guard**
> (`ci/kind/crd-schemas/` + `ci/kind/selftest/validate-cr-schemas{,-bite}.sh`, blocking in
> `infra`) now makes that unknown-field class BITE statically. **BUT the live harness is NOT
> green:** a separate pre-existing bug (F3) fails the chart apply BEFORE the assertions run —
> the N6.1 fail-closed residue check counts kubectl PodSecurity `Warning:` lines (on the
> ADR-0031 packet-capture / seccomp `install-profile` objects) as residue → fail-closed in
> EVERY run, masked by `continue-on-error`. An earlier "green, 2 consecutive" claim was a
> `conclusion`-vs-`outcome` reporting error and is **retracted** (always verify the report-step
> `outcome`, never `conclusion`, for a continue-on-error step). So ADR-0048 §3 Prerequisite A
> is **NOT** met; the §4 bite cannot run until F3 is fixed and the harness reaches
> `outcome=success`. Gate remains **HELD**; PR #94 promotes nothing. Detail:
> `docs/production-audit-2026-07-01/T7-HARNESS-RECOVERY.md` §5.1/§8.

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
| Queue-burst drill: `SKIP: KEDA ScaledObject … absent` | The drill ran on a **non-HA** harness (no `HA=1`, so no KEDA per-queue autoscaling). Expected on the P2 path — the queue-burst/load drill only asserts under `HA=1`. Not a failure. |
| Queue-burst drill: `did NOT scale out … no scale-out` | KEDA did not grow the `discovery` worker Deployment under a 10× burst — a real G-SCA §329 regression (or a disabled/misconfigured trigger). Confirm the `netops-worker-discovery` ScaledObject reconciled Ready, the Sentinel is discovered, and `LLEN discovery` actually reached the burst depth; check `kubectl -n netops get scaledobject,hpa -o wide`. |
| Queue-burst drill: `sibling queue … was STARVED … isolation VIOLATED` | A sibling worker Deployment lost its replica budget to the `discovery` burst — a real per-queue-isolation regression (or the negative control is active). Confirm each queue has its OWN ScaledObject⇄Deployment (no shared scaler); confirm `QUEUE_BURST_DRILL_NEGATIVE_CONTROL` is **not** set on a real run. |
| Queue-burst drill: `p95 … EXCEEDS the … budget` / `NO 1->2-replica improvement` / `HTTP 5xx` | The api did not hold under the reduced-scale load — a §327 regression. Inspect the api Deployment CPU/limits, the HPA, and the api logs; a p95 that does not improve at 2 replicas points at a shared bottleneck (DB/pooler) rather than api CPU. |
| Queue-burst drill: `connection-exhaustion error … budget breached` | The transaction-mode PgBouncer Pooler ran out of server connections under load — a §330 / ADR-0042 §4 regression (or the negative control is active). Confirm `pgbouncer.poolMode: transaction` + the `maxClientConn`/`defaultPoolSize` budget vs the primary's `max_connections`; confirm the negative-control flag is **not** set on a real run. |
| `queue-burst/load bite proof found N violation(s)` | `queue-burst-load-bite.sh` (no cluster) found the drill no longer bites correctly — e.g. the negative control stopped starving a sibling / breaching the budget, or the no-scale-out case passed. The drill is not a real gate until this is green; do **not** trust a live green until the bite proof passes. |
| Upgrade rehearsal: `SKIP: CNPG Cluster … absent` / `api Deployment … absent` | The drill ran on a **non-HA** harness (no `HA=1`, so no CNPG Cluster / api tier). Expected on the P2 path — the upgrade rehearsal only asserts under `HA=1`. Not a failure. |
| Upgrade rehearsal: `N-1 reader (SELECT n1_col) FAILED` / `expand/contract §10 breach` | A migration DROPPED a column an N-1 pod still reads (a contract shipped too early) — a real G-MNT §346 / §10 rolling-upgrade regression (or the negative control is active). Ship the **contract** a release LATER (after the prior version leaves support); confirm `N2_UPGRADE_DRILL_NEGATIVE_CONTROL` is **not** set on a real run. |
| Upgrade rehearsal: `api availability DROPPED … rolling upgrade without downtime VIOLATED` | The api fell below its ≥2-ready floor during the roll — a real §346 downtime regression (or the force-unavail control is active). Confirm `api-pdb` `minAvailable` + the Deployment surge config keep ≥2 serving; confirm `N2_UPGRADE_DRILL_FORCE_API_UNAVAIL` is **not** set on a real run. |
| Upgrade rehearsal: `committed DATA LOSS` / `audit spine REGRESSED` | The migration lost a committed seeded row or truncated/reordered the audit chain — a real §346 / ADR-0038 §3 durability regression. The expand must be additive-only; inspect the migration that ran (`alembic history`) and the audit hash-chain. |
| `n2-upgrade-rehearsal bite proof found N violation(s)` | `n2-upgrade-rehearsal-bite.sh` (no cluster) found the drill no longer bites correctly — e.g. a negative control stopped turning the drill red, or the additive-expand happy path went false-red. The drill is not a real gate until this is green; do **not** trust a live green until the bite proof passes. |
