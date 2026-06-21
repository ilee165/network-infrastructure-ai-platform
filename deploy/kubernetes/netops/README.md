# netops Helm chart (P1 W3 scaffold)

This chart is the **P1 W3 scaffold** of the production Helm chart (ADR-0013 /
ADR-0029). It ships **only** the packet-sandbox OS-isolation workloads
(ADR-0031) and the K8s hardening-round-1 primitives (ADR-0029 §3/§5). The full
per-service GA chart (api/worker/frontend/data stores, the topology
NetworkPolicy edge-set, cert-manager TLS ingress) is **W4** — the values keys
here are the seams W4 grows.

> Single-replica, **not** highly available (HA is P2 per ADR-0029 §0).

## What this scaffold delivers (W3)

| Object | Source | Control |
|---|---|---|
| `Namespace` PSA labels | ADR-0029 §3 | `enforce/audit/warn = restricted` |
| `packet-capture` Deployment | ADR-0031 §1 | `NET_RAW`+`NET_ADMIN`, tainted pool, own SA |
| `packet-analysis` Deployment | ADR-0031 §2 | drop-ALL caps (no add), non-root uid≥10000, RO-rootfs, Localhost seccomp, RO pcap, bounded scratch, resource limits |
| `packet-analysis-seccomp.json` | ADR-0031 §3 | deny-by-default seccomp allow-list |
| `packet-analysis` NetworkPolicy | ADR-0031 §4 | default-deny ingress+egress, DNS+Postgres allows only |
| Node taint + tolerations | ADR-0031 §5 | `NET_RAW` never co-schedules with general pods |
| ServiceAccounts | ADR-0029 §5 / ADR-0031 §1 | one per workload, `automountServiceAccountToken: false`, zero ClusterRoleBinding |
| Admission policy (Kyverno / VAP) | ADR-0029 §5 | no-`latest`, signed-image (data-gated), PSS-deviation allow-list |

## Secure by default = opt-out, never opt-in

Every hardening control defaults to its hardened value (ADR-0029 §0). Disabling
any one is an explicit `values.yaml` override that triggers a Helm `NOTES`
warning. Do **not** flip a default to weaken the baseline.

## Install

```sh
helm install netops deploy/kubernetes/netops \
  --namespace netops --create-namespace \
  --set images.backend.tag=<digest-pinned-release-tag>
```

Prerequisites for the hardened path:

- A **tainted packet node pool**: `node-role.netops/packet=true:NoSchedule`
  with nodes labelled `node-role.netops/packet=true`.
- The **Localhost seccomp profile** installed under the kubelet seccomp root on
  the packet nodes at `<seccomp-root>/netops/packet-analysis-seccomp.json`
  (the file in `seccomp/` here is the source of truth; deploy it to nodes via
  your node-provisioning path / a seccomp-installer DaemonSet in W4).
- **Kyverno** (default `admission.engine=kyverno`) **or** set
  `admission.engine=vap` for a webhook-free ValidatingAdmissionPolicy.

## Key values

| Key | Default | Notes |
|---|---|---|
| `namespaceLabels.podSecurity.enforce` | `restricted` | weakening is a warned opt-out |
| `hardening.securityContext.*` | hardened | reusable per-container context (W4 consumes via the `netops.hardenedSecurityContext` helper) |
| `packet.analysis.*` | full §2 profile | NET_RAW MUST NOT appear here |
| `packet.capture.capabilities.add` | `[NET_RAW, NET_ADMIN]` | capture only |
| `networkPolicy.enabled` | `true` | default-deny egress for analysis |
| `admission.enabled` / `admission.engine` | `true` / `kyverno` | `vap` fallback for webhook-free clusters |
| `admission.signedImages.enabled` | `false` | W6 wires the cosign verifier key |
| `serviceAccounts.automountServiceAccountToken` | `false` | workloads need no K8s API token |

## Policy-as-test

The chart is gated in CI (`.github/workflows/ci.yml` `infra` job) by:
`helm lint` → `helm template` → `kubeconform -strict` → `kube-linter` →
`conftest test` (the Rego in `deploy/kubernetes/policy/rego/` asserts every
control above on the rendered manifests). This is the evidence that flips the
M5 PARTIAL packet-sandbox sign-off (ADR-0031 §7).

Compose lockstep: `deploy/docker/seccomp/packet-analysis-seccomp.json` is the
byte-for-byte mirror of this chart's profile, wired into the `packet-analysis`
Compose service via `security_opt: ["seccomp=..."]` (ADR-0031 §3).
