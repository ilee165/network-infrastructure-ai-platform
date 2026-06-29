# W4-T1 — Ephemeral HA kind topology in CI (CNPG + KEDA + Sentinel + enforcing CNI)

| | |
|---|---|
| **Wave** | P3 W4 — kind HA + drills + gate promotion + upgrade |
| **Owner** | `wf-infra` (strong) |
| **Review tier** | **strong** quality |
| **Depends on** | **W1** (data tier), **W2** (compute) |
| **ADRs** | ADR-0047 (drill harness), ADR-0048 (gate promotion), ADR-0042/0043/0044, ADR-0029 (Helm GA); extends the P2 `kind-harness.sh` |
| **PRODUCTION.md** | §3, §8, §9, §11 |
| **Status** | Proposed |

## Objective

Build the **ephemeral HA kind cluster** the W4 drills + gate promotion run against:
the P2 kind-harness extended to stand up the **CloudNativePG operator, KEDA, Redis
Sentinel, and an enforcing CNI** (the P2 mTLS + NetworkPolicy harness already needs
the enforcing CNI), then deploy the chart at **reduced scale**. This is the
substrate; the drills (T3–T8) and the gate promotion (T2) plug into it.

## Scope

**In** — extend `kind-harness.sh` / CI to install the CNPG operator + KEDA + a
Sentinel deployment + an enforcing CNI (Calico/Cilium) on kind; deploy the chart
(reduced replica counts); bring-up readiness gating with `set -o pipefail` +
`test -s` on every piped step (**L5**); `lookup`/idempotent dev secrets (**L4**);
teardown. Reliable enough to host **blocking** gates (the W4-T2 prerequisite).

**Out** — the individual drills (T3–T8); the gate promotion commit (T2); the
non-HA P2 harness (this extends it, doesn't replace its mTLS/collector assertions).

## Requirements (grounded in ADR-0047/0048, PRODUCTION.md §3/§9)

1. **HA components on kind** — CNPG operator (PG 1+2), KEDA, Sentinel, enforcing CNI
   all come up green; chart deploys at reduced scale.
2. **Reliable for blocking gates** — bring-up is deterministic + retried where
   flaky; this reliability is the explicit prerequisite for W4-T2 promotion.
3. **L5 pipefail + `test -s`** on every apply/wait/assert pipe (a piped failure must
   not be masked as success).
4. **L4 idempotent secrets**; **L1 local-first** — run the harness locally/in a
   kind-capable runner before it gates; where kind can't run on the authoring host,
   say so and rely on the CI runner.
5. **Reduced-scale, named** — state the replica counts/scale the topology runs at
   (the §0 posture).

## Contracts / artifacts

- Extended `kind-harness.sh` + CI job standing up the HA topology; reduced-scale
  values overlay; teardown.

## Test & gate plan

- The HA topology comes up green in CI (CNPG/KEDA/Sentinel/CNI ready); pipefail +
  `test -s` on each step.
- Local kind run first where possible (L1); otherwise documented CI-only.

## Exit criteria

- [ ] kind stands up CNPG (1+2) + KEDA + Sentinel + enforcing CNI; chart deploys at reduced scale.
- [ ] Bring-up reliable enough to host blocking gates (the W4-T2 prerequisite); L5 pipefail + `test -s` throughout.
- [ ] L4 idempotent secrets; scale stated; one atomic commit.

## Workflow

`wf-infra` (strong) → **`wf-quality-reviewer` (strong)** + `wf-spec-reviewer` → `wf-fixer` (strong) if findings → `wf-verifier` → one atomic commit.

## Risks

- **Flaky bring-up** → can't promote any gate to blocking (blocks every merge). The
  reliability bar is the gate to W4-T2.
- **L5 masked failure** → a half-up cluster reported "ready", drills false-green.
- **kind can't run on host** → don't assume CI passes; validate on a kind-capable
  runner (L1).
