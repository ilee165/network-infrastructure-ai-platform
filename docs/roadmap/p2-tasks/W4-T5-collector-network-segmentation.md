# W4-T5 — Collector Network Segmentation (default-deny egress NetworkPolicy, deny asserted on kind)

| | |
|---|---|
| **Wave** | P2 W4 — Security hardening + kind validation (network stream) |
| **Owner** | `wf-infra` (strong — security-semantic NetworkPolicy; egress blast radius) |
| **Review tier** | **strong** spec + **strong** quality (secret-surface: security-semantic egress policy) |
| **Depends on** | **W4-T3** (kind harness + enforcing CNI) + **W0-T8** (ADR-0041) |
| **ADRs** | ADR-0041 (the contract this builds), ADR-0029 (Helm GA chart, PSS/NetworkPolicy baseline), ADR-0008 (Celery workers / collectors), ADR-0013 (deployment) |
| **PRODUCTION.md** | §9 (collector network segmentation), §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement exactly what **ADR-0041** ratified: a **default-deny egress
NetworkPolicy** on the collector/worker pods that **allows only** the device
management subnet(s) plus the named in-cluster services, so a compromised collector
cannot exfiltrate or pivot. The **deny is asserted on the W4-T3 kind cluster** (with
its enforcing CNI) — an allowed egress succeeds, an arbitrary external egress is
**blocked**.

## Scope

**In** (a Helm-rendered `NetworkPolicy` + a T5 assertion plugged into the W4-T3
runner)
- **Default-deny egress** on the collector/worker pods (selector per ADR-0041);
  **allow only**: the device **management subnet(s)** (ipBlock CIDR or selectors as
  ADR-0041 fixed) **plus** the required in-cluster endpoints (Postgres / Redis /
  Neo4j as needed). Everything else denied.
- **Selector model** exactly as ADR-0041 decided (which pod labels the policy binds;
  how the mgmt-subnet allow is expressed) — no broadening here.
- **kind assertion** (T5's plug into the W4-T3 runner): an allowed egress (mgmt
  subnet / named service) **succeeds**; a denied egress (arbitrary external) is
  **blocked** — the deterministic enforcement bite, valid **only because W4-T3
  installed an enforcing CNI** (ADR-0041 L1).

**Out**
- ADR / policy-shape / CNI decision → **W0-T8** (this implements it).
- kind harness + CNI install → **W4-T3** (this depends on it).
- Ingress / api-pod policy beyond the ADR-0029 baseline → out unless ADR-0041 scoped in.
- HA/scale-out networking → **P3-Platform** (§0).

## Requirements (grounded in ADR-0041, ADR-0029, P1-W4-LESSONS L1)

1. **Default-deny, explicit-allow** (secure-by-default): the policy denies all egress
   and re-permits only the enumerated destinations; an un-listed destination is
   unreachable — asserted on kind.
2. **Enforcement is real, not nominal** (**L1**): the deny assertion runs on the
   W4-T3 enforcing-CNI cluster; without it the policy is inert and the test is
   false-green. T5 must depend on (and run after) the W4-T3 CNI self-test.
3. **Least exposure** (§9): the allow-list is the mgmt subnet + named cluster
   services — **not** all RFC1918, not the general internet.
4. **Manifest-policy clean** (ADR-0029): kubeconform / conftest / kube-linter stay
   green on the new policy.
5. **Pipe-safe assertion** (P1-W4-LESSONS **L5**): the egress allow/deny probe pipes
   use `set -o pipefail` + `test -s` so a masked exit reads honestly.

## Contracts / artifacts

- `NetworkPolicy` resource(s) (Helm template): default-deny egress + minimal allow.
- A T5 assertion (allowed egress succeeds / arbitrary egress blocked) in the W4-T3 runner.

## Test & gate plan (infra gates — not Python-TDD)

- **kind deny assertion** (the exit bite): on the enforcing-CNI cluster, a mgmt-subnet
  / named-service egress **succeeds**; an arbitrary external egress is **blocked**.
- **Allow-list minimality**: a test/lint asserts the allow set is the enumerated
  destinations only (no `0.0.0.0/0`, no blanket RFC1918).
- Manifest-policy gates green: kubeconform / conftest / kube-linter; helm lint clean.
- **Depends on the W4-T3 CNI self-test** passing first (else the deny is meaningless).
- L5 pipefail / `test -s` on the egress probe; local run first (L1, via W4-T3).

## Exit criteria

- [ ] Default-deny egress NetworkPolicy on collector/worker pods; allow-list = mgmt
      subnet + named cluster services only.
- [ ] Selector + mgmt-subnet expression match ADR-0041 (no broadening).
- [ ] kind deny assertion bites (allowed succeeds / arbitrary blocked) on the
      enforcing-CNI cluster; runs after the W4-T3 CNI self-test.
- [ ] Allow-list-minimality check green; manifest-policy gates green.
- [ ] L5 pipefail applied; one atomic commit.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-infra` (strong) implements → **`wf-spec-reviewer` (strong) +
`wf-quality-reviewer` (strong)** → `wf-fixer` (strong) if findings → `wf-verifier`
→ **one atomic commit**.

## Risks

- **kind default CNI does not enforce NetworkPolicy** (**L1**): the deny test passes
  whether or not the policy works — a false-green that defeats the whole control.
  T5's assertion is only valid on the W4-T3 enforcing-CNI cluster; depend on its
  self-test.
- **Over-broad allow-list** (e.g. allow all RFC1918) reopens the pivot path the
  control exists to close — keep it to the mgmt subnet + named services; the
  minimality check is the guard.
