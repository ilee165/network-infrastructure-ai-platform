# Runbook — Ephemeral in-CI kind cluster harness (W4-T3)

> Operator/developer procedure for the ADR-0041 §2/§3 + ADR-0039 §6 kind harness: how it brings up a throwaway cluster with an **enforcing CNI**, proves the CNI actually enforces NetworkPolicy (the **CNI self-test bite**), applies the chart, and runs the assertion-runner that **W4-T4 (mTLS handshake)** and **W4-T5 (collector egress deny)** plug their assertions into. Also records why the live kind job is **not yet a blocking gate** and what P3-Platform must do to promote it (re-deferred from W5-T3). Cheap-scope only — handshake + deny; HA/scale/soak are P3-Platform.

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
| CI job (P2) | `.github/workflows/ci.yml` job `kind-harness` (**non-blocking** — see "Gate status" below) |
| CI job (HA, P3 W4-T1) | `.github/workflows/ci.yml` job `kind-harness-ha` (**non-blocking live** — see "HA topology" + "Gate status") |
| Cluster name | `netops-w4` (`CLUSTER_NAME` override) |
| HA operator installer | `ci/kind/ha/install-operators.sh` (CloudNativePG `1.29.1` + KEDA `2.16.1`, pinned; `CNPG_VERSION`/`KEDA_VERSION` override) |
| HA readiness gate | `ci/kind/ha/wait-ha-ready.sh` (a half-up topology must NOT read ready — L5) |
| HA overlay validator | `ci/kind/ha/validate-ha-overlay.sh` (static render + reduced-scale count bite) |
| Reduced-scale HA overlay | `deploy/kubernetes/netops/values-kind-ha.yaml` (`HA_VALUES` override) |

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
`kind-harness-ha` job is **continue-on-error** until **W4-T2** exercises it green
and promotes it.

## Gate status — NON-BLOCKING (CI-only / deferred), and how to promote it

The live kind path (steps 1-6) is **deliberately not a blocking gate**:

- The `kind-harness` job is **absent from the `all-gates` required-check aggregator's `needs` list**, and its live `kind-harness.sh` step is `continue-on-error: true`.
- **Why:** the live kind/CNI path could **not be validated locally on the W4-T3 authoring host** (Windows, no Docker / no Linux kind cluster). P1-W4-LESSONS **L1** is explicit: validate a new gating CI tool LOCALLY before pushing it as required — the local gate set is not the CI gate set, and CNI install / shell quoting often break differently in CI. Making this a required gate now would let a CI-only kind/CNI bring-up quirk mask the entire suite by flipping the required aggregator red on a path nobody has run green.
- **What IS enforced now:** the static `validate-harness.sh` step runs on every push and is **blocking within the job** (it needs no cluster and reliably bites a silently weakened harness). The static manifest gates (helm lint / kubeconform / kube-linter / conftest) on the chart remain green via the `infra` job.

**Promotion (re-deferred → P3-Platform):** the W5-T3 release auditor reviewed this and **re-deferred promotion to P3-Platform** — gating an enforcing-CNI kind cluster as a required check needs a certified cluster to run reliably, which this phase's no-hardware host does not have (`P2-RELEASE-READINESS.md` G-SEC). Once the live run is exercised on a Linux/Docker or certified-CNI cluster and the L1 local-validation lesson is satisfied,
1. drop `continue-on-error: true` from the "Run kind harness" step, and
2. add `kind-harness` to the `all-gates` `needs` list (`.github/workflows/ci.yml`).

This is now a **P3-Platform** readiness item (re-deferred from W5-T3); until then the live kind validation is recorded as **CI-only / deferred-accepted** alongside the project's prior live-lab deferrals (e.g. SpatiumDDI live-lab, M5 live-lab acceptance).

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
