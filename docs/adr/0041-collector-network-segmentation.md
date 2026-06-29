# ADR-0041: Collector Network Segmentation (NetworkPolicy Egress)

**Status:** Accepted | **Date:** 2026-06-25 (Accepted 2026-06-29) | **Milestone:** P2 W0 (Accepted P2 W5)

## Context

`PRODUCTION.md` §9 requires the collector/worker pods — the components that reach out
to managed devices — to be confined so a compromised collector cannot exfiltrate or
pivot. Today they have no egress restriction. This ADR is the design gate; the build
is **W4-T5**, validated on the **W4-T3** ephemeral in-CI kind cluster
(`P2-SECURITY-PLAN.md` §3). A security-semantic NetworkPolicy is a secret surface
(strong review).

Bounded by ADR-0029 (K8s/Helm GA chart, PSS/NetworkPolicy baseline), ADR-0008
(Celery workers / collectors), ADR-0013 (deployment).

## Decision

**A default-deny egress NetworkPolicy on the collector/worker pods allows egress
ONLY to the device management subnet(s) and the named in-cluster services (Postgres,
Redis, Neo4j as needed); everything else is denied. Enforcement REQUIRES an enforcing
CNI — kind's default CNI does not enforce NetworkPolicy — so the W4-T3 harness
installs Calico/Cilium and the W4-T5 deny is asserted there.**

### 1. Default-deny egress, explicit allow-list

A `NetworkPolicy` selecting the collector/worker pods (by their existing app labels)
sets `policyTypes: [Egress]` with a default-deny posture and re-permits only:

- the device **management subnet(s)** — expressed as `ipBlock` CIDR(s) (the operator
  configures the mgmt CIDR via chart values), the only external destination
  collectors legitimately reach; and
- required **in-cluster services** — Postgres, Redis, Neo4j (and kube-dns for name
  resolution) via namespace/pod selectors.

Any unlisted destination (arbitrary internet, other namespaces) is unreachable. A
compromised collector cannot exfiltrate or pivot beyond the mgmt subnet + named
services.

### 2. Enforcing CNI is mandatory — the load-bearing requirement

**NetworkPolicy is not enforced by kind's default CNI (kindnet).** The W4-T3 kind
harness MUST install an enforcing CNI (Calico or Cilium); without it the policy is
inert and the W4-T5 deny test is **false-green**. This is the single most important
note in this ADR (P1-W4-LESSONS **L1**). The W4-T3 harness includes a **CNI
self-test** (a harness-applied default-deny must block a known egress) gating the
rest of the run. The production cluster is likewise assumed to run an enforcing CNI
(ADR-0029).

### 3. kind assertion (W4-T5 on the W4-T3 cluster)

On the enforcing-CNI cluster: an allowed egress (mgmt subnet / named service)
**succeeds**; a denied egress (arbitrary external) is **blocked** — the deterministic
enforcement bite. The assertion runs only after the W4-T3 CNI self-test passes.

### 4. Scope boundary

Ingress policy and api-pod policy beyond the ADR-0029 baseline are **out** of this
ADR (collector egress only). HA/scale-out networking is re-scoped to P3-Platform
(§0). Manifest-policy gates (kubeconform / conftest / kube-linter) stay green on the
new policy (named for W4-T5).

## Consequences

**Positive**
- Default-deny egress bounds a compromised collector to the mgmt subnet + named
  services — closes the exfiltration/pivot path (§9).
- The mandated enforcing CNI + CNI self-test (§2) make the kind deny test actually
  bite, not false-green.
- Cheap, deterministic G-SEC bite on kind without HA/scale hardware.

**Negative**
- Requires an enforcing CNI in the harness (and prod) — an operational dependency
  (ADR-0029 assumption made explicit).
- An over-broad allow-list (e.g. all RFC1918) silently reopens the pivot path; the
  W4-T5 allow-list-minimality check is the guard.
- The mgmt CIDR is operator-configured; a misconfigured CIDR could over- or
  under-permit (documented in the W4-T5 values/runbook).

## Alternatives considered

1. **Rely on kindnet / assume NetworkPolicy is enforced.** Rejected (§2): kindnet
   does not enforce NetworkPolicy — the deny test would pass whether or not the
   policy works. An enforcing CNI + self-test is mandatory.
2. **Broad allow-list (all RFC1918 / all internet-except-X).** Rejected: reopens the
   pivot/exfiltration path the control exists to close; allow-list is the mgmt subnet
   + named services only.
3. **Host firewall / external segmentation instead of NetworkPolicy.** Rejected for
   P2: NetworkPolicy is the in-cluster, chart-rendered, kind-validatable control;
   external segmentation is complementary, not a substitute, and not kind-testable.
4. **Egress proxy/gateway for collectors.** Rejected for P2: heavier to operate; a
   default-deny NetworkPolicy meets §9 now. An egress gateway is a future option if
   richer egress policy is needed.
