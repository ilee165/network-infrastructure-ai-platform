# W4-T3 — Ephemeral In-CI kind/k3d Cluster Harness (apply manifests + enforcement assertions)

| | |
|---|---|
| **Wave** | P2 W4 — Security hardening + kind validation (network stream) |
| **Owner** | `wf-infra` (strong — infra/CI gating; enforcing-CNI correctness) |
| **Review tier** | **strong** quality (the harness is the bite for T4 + T5; a false-green here defeats both) |
| **Depends on** | **W0-T6** (ADR-0039 mTLS) + **W0-T8** (ADR-0041 segmentation — the CNI requirement); **lands before W4-T4 + W4-T5** |
| **ADRs** | ADR-0039 §kind-assertion, ADR-0041 §CNI-enforcement, ADR-0029 (Helm GA chart + manifest gates), ADR-0013 (deployment) |
| **PRODUCTION.md** | §9 (validation infra), §11 G-SEC |
| **Status** | Proposed |

## Objective

Build the **ephemeral in-CI kind/k3d cluster harness** that the two enforcement
tasks assert against: it spins a throwaway cluster **with an enforcing CNI**
(Calico / Cilium per ADR-0041 — kind's default CNI does **not** enforce
NetworkPolicy), applies the chart's manifests, runs the enforcement assertions
(handshake / deny), and tears down. This is the "kind for cheap" half — it bites
**mTLS handshake** (T4) and **NetworkPolicy deny** (T5) only; expensive
HA/scale/soak drills are **P3-Platform** (§0).

## Scope

**In** (`.github/workflows/` job + a harness script/manifests under `deploy/` or
`ci/`, an assertion-runner the T4/T5 tasks extend)
- **Cluster bring-up**: a CI job that creates an ephemeral kind (or k3d) cluster,
  **installs an enforcing CNI** (the single most important step — ADR-0041 L1), and
  tears it down on exit (success or failure).
- **Manifest apply**: render the Helm chart and apply the P2-relevant manifests
  (postgres + api/worker + the policies T4/T5 add) into the cluster.
- **Assertion-runner scaffold**: a reusable harness entrypoint that T4 (mTLS
  handshake / plaintext-refusal) and T5 (egress allow / deny) plug their assertions
  into; exit non-zero on any failed assertion.
- **A self-test of the CNI** (the L1 guard): a baseline default-deny applied by the
  harness itself **must block** a known egress before T5 trusts it — proving the CNI
  enforces, not just admits, NetworkPolicy. If the block does not happen, the job fails.

**Out**
- The mTLS manifests + handshake assertion → **W4-T4**.
- The collector NetworkPolicy + deny assertion → **W4-T5**.
- HA / scale / 30-day soak / load drills → **P3-Platform** (§0).

## Requirements (grounded in ADR-0039, ADR-0041, P1-W4-LESSONS L1/L5)

1. **Enforcing CNI installed** (ADR-0041 L1): the harness installs Calico/Cilium;
   a **CNI self-test** (harness-applied default-deny blocks a known egress) gates the
   rest of the run — without it every downstream deny test is false-green.
2. **Run locally before gating** (P1-W4-LESSONS **L1**): the harness is validated on
   a local kind cluster before it is pushed as a gating CI job — local gate set ≠ CI
   gate set; do not discover CNI/quoting breakage in CI.
3. **Pipe-safe** (P1-W4-LESSONS **L5**): every `kubectl apply | …` / assertion pipe
   uses `set -o pipefail` + `test -s <out>`; a masked exit code reads as green.
4. **Ephemeral + isolated**: the cluster is created and destroyed within the job;
   no state leaks between runs; teardown runs even on assertion failure (trap/`always`).
5. **Cheap-scope only** (§0): the harness asserts handshake + deny; it does **not**
   attempt failover / soak / scale — those are named-deferred to P3-Platform.

## Contracts / artifacts

- A CI workflow job (kind/k3d create → CNI install → CNI self-test → apply → assert
  → teardown).
- A harness script + assertion-runner entrypoint reused by T4/T5.
- The enforcing-CNI install manifest/step (Calico or Cilium per ADR-0041).

## Test & gate plan (infra gates — not Python-TDD)

- **Local run first** (L1): the full harness passes on a local kind cluster before
  the CI job is marked gating.
- **CNI self-test bites**: with the enforcing CNI, a harness default-deny blocks a
  known egress; **remove the CNI and the self-test must fail** (proves the guard
  works, not just that the cluster is up).
- Manifest-policy gates green: kubeconform / conftest / kube-linter on rendered
  manifests; helm lint clean.
- Teardown verified on a forced mid-run failure (no leaked cluster).
- L5 pipefail / `test -s` on every apply+assert pipe.

## Exit criteria

Legend: `[x]` met as delivered · `[~]` **live-validation deferred** (artifact + CI
job authored, but the live kind path was NOT observed on the W4-T3 authoring host —
Windows, no Docker / no Linux kind — and is named-deferred to the W5 release auditor;
see `docs/runbooks/kind-harness.md` "Gate status — NON-BLOCKING" and ADR-0041 L1
"do not gate an unvalidated harness"). A `[~]` item is honestly NOT reported as
satisfied.

- [x] CI job authored that creates + tears down an ephemeral kind/k3d cluster
      (teardown on failure too, via `trap teardown EXIT INT TERM`). `[~]` the
      live create/teardown was not observed on this host.
- [~] Enforcing CNI (Calico) install + **CNI self-test bite** authored, but the
      live bite (default-deny actually blocking egress on Calico, and the self-test
      FAILING when the CNI is removed) has **not been observed on a live cluster** —
      live-validation deferred to W5 (see runbook). NOTE: the pre-fix harness could
      never reach the bite because `kind create … --wait 120s` timed out on the
      CNI-less node (fixed in this commit by dropping `--wait`); the live path is
      now correctly ordered but still un-run here.
- [x] Chart manifests render + apply step present; assertion-runner scaffold present
      (the static validator exercises render-shape invariants).
- [~] Harness validated **locally** before gating (L1): **deferred** — the static
      `validate-harness.sh` is the only piece run on this host; the live harness was
      not. Consistent with L1, the CI `kind-harness` job is left NON-blocking
      (`continue-on-error` + absent from the required aggregator) until a Linux/Docker
      host or green CI run satisfies the local-validation lesson. L5 pipefail on all
      pipes: met (asserted by the validator).
- [x] helm lint / kubeconform / kube-linter green (run on this host; conftest/OPA
      policies are not present in the repo); one atomic commit.
- [~] **Teardown on a forced mid-run failure**: the `trap` is authored and asserted
      statically, but firing it on a live mid-run failure was not observed here —
      live-validation deferred to W5.

## Workflow (P2-SECURITY-PLAN.md §3)

`wf-infra` (strong) implements → **`wf-quality-reviewer` (strong)** (single strong
quality review — infra/CI gating) → `wf-fixer` (strong) if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **kind default CNI admits but does not enforce NetworkPolicy** (L1): the single
  biggest false-green risk. The CNI self-test is the proof the harness enforces;
  T5's deny test is meaningless without it.
- **Gating a harness that only ran in CI** (L1): CNI install / shell quoting often
  breaks differently in CI; validate locally first.
- **Leaked clusters / cost**: a teardown that skips on failure leaks ephemeral
  clusters — teardown must run in an `always`/trap block.
