# W0-T8 — ADR-0041 Collector Network Segmentation (NetworkPolicy egress)

| | |
|---|---|
| **Wave** | P2 W0 — ADRs / re-scope (design gate) |
| **Owner** | `wf-implementer` |
| **Review tier** | **strong** spec + **strong** quality (security-semantic NetworkPolicy — the egress blast radius) |
| **Depends on** | — (independent of T1–T7) |
| **ADRs** | ADR-0029 (K8s/Helm GA chart + hardening, PSS/NetworkPolicy baseline), ADR-0008 (Celery workers / collectors), ADR-0013 (deployment) |
| **PRODUCTION.md** | §9 (collector network segmentation), §11 G-SEC |
| **Status** | Proposed |

## Objective

Decision record for confining the **collector / worker** pods (the components that
reach out to managed devices) with a **default-deny egress NetworkPolicy** that
allows only the management subnet plus required in-cluster services. Decides the
policy shape and the CNI requirement for enforcement. Design gate; build is
**W4-T5** (validated on the W4-T3 kind cluster).

## Scope

**In**
- **Default-deny egress** on collector/worker pods; **allow only**: the device
  **management subnet(s)** (the only place collectors should reach out to) plus
  required in-cluster endpoints (Postgres, Redis, Neo4j as needed). Everything
  else denied — a compromised collector cannot exfiltrate or pivot.
- **Policy selector model:** which pods the policy binds (labels), and how the
  mgmt-subnet allow is expressed (ipBlock CIDR vs namespace/pod selectors).
- **CNI enforcement requirement** (P1-W4-LESSONS **L1** territory): NetworkPolicy
  is **not enforced by kind's default CNI** — the ADR records that the W4-T3 kind
  harness must install an enforcing CNI (Calico / Cilium) or the deny assertion
  silently passes (a gate that does not bite). State the prod-CNI assumption too.
- **kind assertion** (W4): an allowed egress (mgmt subnet) succeeds; a denied
  egress (arbitrary external) is **blocked** — the deterministic enforcement bite.

**Out**
- Implementation (NetworkPolicy manifests, kind CNI install, deny assertion) →
  **W4-T5** (depends on the **W4-T3** kind harness).
- Ingress policy / api-pod policy beyond the baseline (ADR-0029) — out unless the
  ADR scopes it in.
- HA/scale-out networking → **P3-Platform** (§0).

## Requirements (grounded in ADR-0029, P1-W4-LESSONS L1)

1. **Default-deny, explicit-allow** (secure-by-default): the policy denies all
   egress and re-permits only the enumerated destinations; an un-listed
   destination is unreachable.
2. **Enforcement is real, not nominal** (L1): the ADR mandates an enforcing CNI on
   the W4-T3 kind cluster; without it the NetworkPolicy is inert and the deny test
   is false-green. This is the single most important note in the ADR.
3. **Least exposure** (PRODUCTION.md §9): collectors reach the mgmt subnet, not the
   general internet; required cluster services are named, nothing broader.
4. **Manifest-policy clean** (ADR-0029): kubeconform / conftest / kube-linter stay
   green on the new policy (named for W4-T5).

## Contracts / artifacts

- `NetworkPolicy` resource(s) (Helm-rendered): default-deny egress + allow rules.
- kind-harness CNI requirement (recorded for W4-T3 / W4-T5).

## Validation / Test & gate plan (ADR review — strong)

- Repo ADR template; the **CNI-enforcement requirement** is explicit and tied to
  W4-T3 (so the W4-T5 deny test actually bites — L1).
- Allow-list is minimal and enumerated; default-deny is the base.
- markdownlint; ADR index updated.

## Exit criteria

- [ ] ADR-0041 written; status **Proposed**.
- [ ] Default-deny-egress + minimal allow-list (mgmt subnet + named services) fixed.
- [ ] Pod-selector + mgmt-subnet expression (ipBlock vs selectors) decided.
- [ ] **CNI-enforcement requirement** for the W4-T3 kind cluster recorded (L1).
- [ ] kind deny/allow assertion specified for W4-T5; manifest gates named.
- [ ] ADR index updated; markdownlint green.

## Workflow (P2-SECURITY-PLAN.md §3, secret-surface escalation)

`wf-implementer` writes ADR → **`wf-spec-reviewer` (strong) + `wf-quality-reviewer`
(strong)** → `wf-fixer` (strong) if findings → `wf-verifier` → **one atomic commit**.

## Risks

- **kind default CNI does not enforce NetworkPolicy** (L1): the deny test passes
  whether or not the policy works — a false-green that defeats the whole control.
  The ADR must require an enforcing CNI; W4-T3 installs it; W4-T5 proves a deny
  actually blocks.
- **Over-broad allow-list** (e.g. allow all RFC1918) reopens the pivot path the
  control exists to close; keep the allow-list to the mgmt subnet + named services.
