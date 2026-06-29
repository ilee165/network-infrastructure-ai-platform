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
| Static validator | `ci/kind/selftest/validate-harness.sh` (no cluster; asserts the harness invariants — the policy-as-test bite) |
| CI job | `.github/workflows/ci.yml` job `kind-harness` (**non-blocking** — see "Gate status" below) |
| Cluster name | `netops-w4` (`CLUSTER_NAME` override) |

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
ci/kind/selftest/validate-harness.sh     # static — no cluster; should pass
ci/kind/kind-harness.sh                  # full live run (≈3-6 min)
KEEP_CLUSTER=1 ci/kind/kind-harness.sh   # keep the cluster up to poke at it
kind delete cluster --name netops-w4     # manual teardown after KEEP_CLUSTER
```

## How W4-T4 / W4-T5 add assertions

Drop an executable `*.sh` into `ci/kind/assertions/checks/` that sources `../lib.sh` and asserts via the helpers (see `checks/README.md` for the contract). The runner picks it up automatically. Examples:

- **W4-T4 mTLS** — `assert_handshake_ok` (valid-cert client connects) and `assert_handshake_refused` (plaintext / wrong-CA client is rejected by Postgres; ADR-0039 §3/§6).
- **W4-T5 egress** — `assert_egress_allowed` (mgmt-subnet / named service reachable) and `assert_egress_blocked` (arbitrary external destination denied; ADR-0041 §3). These are meaningful ONLY because step 3 proved the CNI enforces.

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
