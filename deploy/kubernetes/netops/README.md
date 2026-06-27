# netops Helm chart (P1 GA)

This is the **GA** production Helm chart for the AI Network Operations Platform
(ADR-0013 / ADR-0029). It ships the full per-service workload set
(api/worker/frontend + toggleable postgres/neo4j/redis/ollama data stores), the
§3.1 topology NetworkPolicy edge-set, cert-manager TLS ingress, least-privilege
RBAC + admission policy, and the packet-sandbox OS-isolation workloads
(ADR-0031), all **hardened by default**.

> ## Single-replica — NOT highly available
>
> **P1 GA is single-replica.** Every Deployment/StatefulSet runs **one** replica
> and the chart ships **no** HPA, KEDA, operator (CloudNativePG / Sentinel), or
> PodDisruptionBudget. A node loss takes a service down until it reschedules —
> there is **no in-cluster HA**. This is an accepted P1 limitation: **HA is P2**
> (ADR-0029 §0/§1, Alt #3). The `services.<svc>.replicas` keys are the *seam* P2
> widens with autoscalers/operators; raising a replica count alone gives you
> neither autoscaling nor a disruption budget (the chart emits a NOTES warning if
> you do). Do **not** mistake GA for highly-available.

## What this chart delivers (GA)

| Object | Source | Control |
|---|---|---|
| `api` Deployment + Service | ADR-0029 §1 | stateless uvicorn, reached ONLY via the frontend nginx reverse proxy (ADR-0012 §2); hardened container securityContext, resource req+limits, ADR-0015 §4 probes |
| `worker` Deployment | ADR-0029 §1 | celery over the five `restricted`-compliant queues (`discovery,config,docs,topology,system`); `packet` is its own ADR-0031 workload, never here |
| `frontend` Deployment + Service | ADR-0012 §2 | nginx static Vite output + same-origin reverse proxy for `/api` + WS; the SINGLE ingress target |
| `postgres`/`neo4j`/`redis` StatefulSets | ADR-0013 §4 | toggleable (`services.<svc>.enabled=false` → external/operator-managed); hardened, resource req+limits, native probes |
| `ollama` StatefulSet | ADR-0009 | OPT-IN (`enabled:false`, replicas 0 by default); external provider is the default posture |
| `Ingress` + cert-manager `Certificate` | ADR-0029 §4 | ONE HTTPS-only Ingress → frontend; ssl-redirect + HSTS; TLS Secret cert-manager-managed (no key in values); all Services ClusterIP |
| `NetworkPolicy` set | ADR-0029 §2 / ADR-0041 | `default-deny-all` floor + one additive allow per §3.1 arrow; DNS-only egress; collector/worker mgmt-subnet egress (`ipBlock` CIDR only, device-mgmt ports; ADR-0041 — deny asserted on the W4-T3 kind cluster); external-LLM egress opt-in default-off |
| `Namespace` PSA labels | ADR-0029 §3 | `enforce/audit/warn = restricted` (install namespace); capture namespace relaxed for its NET_RAW deviation |
| `packet-capture` Deployment | ADR-0031 §1 | `NET_RAW`+`NET_ADMIN`, tainted pool, own SA, confined management-subnet egress |
| `packet-analysis` Deployment | ADR-0031 §2 | drop-ALL caps (no add), non-root uid≥10000, RO-rootfs, Localhost seccomp, RO pcap, bounded scratch, resource limits, default-deny egress |
| `packet-analysis-seccomp.json` | ADR-0031 §3 | deny-by-default seccomp allow-list |
| ServiceAccounts | ADR-0029 §5 / ADR-0031 §1 | one per workload, `automountServiceAccountToken: false`, zero ClusterRole(Binding) |
| Admission policy (Kyverno / VAP) | ADR-0029 §5 | no-`latest`, signed-image (data-gated), PSS-deviation allow-list naming EXACTLY the packet sandbox |
| pgBackRest backup `CronJob`s + `ConfigMap` (W5-T1) | ADR-0030 §1/§4 | continuous WAL archiving (postgres `archive_mode=on` + `archive_command`) + weekly-full / daily-incr backups → MinIO/S3, repo `aes-256-cbc` encryption, `pgbackrest verify` GATES every job; ON by default (`backup.postgres.enabled`); own `backup-sa`; confined egress NetworkPolicy; all repo secrets by external-secret reference |

## Secure by default = opt-out, never opt-in

Every hardening control defaults to its hardened value (ADR-0029 §0): per-container
`runAsNonRoot`, `allowPrivilegeEscalation:false`, drop-ALL caps,
`readOnlyRootFilesystem:true`, seccomp `RuntimeDefault`, resource requests+limits;
namespace-wide `restricted` PSS; default-deny NetworkPolicies; TLS-only Ingress;
signed-image admission. Disabling any one is an explicit `values.yaml` override
that triggers a Helm `NOTES` warning. Do **not** flip a default to weaken the
baseline.

## Install

```sh
helm install netops deploy/kubernetes/netops \
  --namespace netops --create-namespace \
  --set images.backend.tag=<digest-pinned-release-tag> \
  --set ingress.host=netops.your-org.example \
  --set secrets.existingSecret=<your-platform-secret>   # external-secrets/CSI-populated
```

Prerequisites for the hardened path:

- **cert-manager** + an Issuer/ClusterIssuer (`ingress.tls.issuerRef`) for the
  TLS Ingress (no key material ever passes through Helm values).
- An **ingress controller** matching `ingress.className` (default `nginx`).
- **Kyverno** (default `admission.engine=kyverno`) **or** set
  `admission.engine=vap` for a webhook-free ValidatingAdmissionPolicy.
- A **tainted packet node pool**: `node-role.netops/packet=true:NoSchedule`
  with nodes labelled `node-role.netops/packet=true`.
- The **Localhost seccomp profile** seeded on the packet nodes at
  `<kubelet-seccomp-root>/netops/packet-analysis-seccomp.json` — the bundled
  `seccompInstaller` DaemonSet (default on) copies `seccomp/` here onto each node;
  disable it only if your nodes are pre-seeded out-of-band.
- A **platform Secret** referenced by `secrets.existingSecret`, populated by the
  external-secrets operator or a CSI secrets-store backed by your KMS/Vault
  (ADR-0029 §6). Leaving it empty renders a **dev-only** generated Secret (warned).

## Key values

| Key | Default | Notes |
|---|---|---|
| `services.<svc>.replicas` | `1` | SINGLE-REPLICA; raising it is the P2 HA seam (warned) |
| `services.<svc>.enabled` | `true` (ollama `false`) | data stores toggleable to external/operator-managed |
| `services.<svc>.type` | `ClusterIP` | NodePort/LoadBalancer is a warned opt-out (Ingress is the single front door) |
| `hardening.securityContext.*` | hardened | reusable per-container context (every workload consumes the `netops.hardenedSecurityContext` helper) |
| `namespaceLabels.podSecurity.enforce` | `restricted` | weakening is a warned opt-out |
| `ingress.enabled` / `ingress.host` | `true` / placeholder | set `host` to your real FQDN |
| `ingress.tls.certManager.enabled` / `issuerRef` | `true` / placeholder | cert-manager issues the TLS Secret; no key in values |
| `networkPolicy.enabled` | `true` | default-deny floor + §2 per-edge allows |
| `networkPolicy.collectorEgress.enabled` | `true` | collector/worker default-deny egress to the device mgmt subnet (ADR-0041); disabling is a warned opt-out |
| `networkPolicy.collectorEgress.managementCidrs` | `[10.0.0.0/8]` | device mgmt subnet `ipBlock` CIDR(s) — NARROW to your real range; `0.0.0.0/0` and blanket RFC1918 are rejected by the allow-list-minimality policy |
| `networkPolicy.externalLlmEgress.enabled` | `false` | OPT-IN; local-first/air-gapped is the default |
| `admission.enabled` / `admission.engine` | `true` / `kyverno` | `vap` fallback for webhook-free clusters |
| `admission.signedImages.enabled` | `false` | W6 wires the cosign verifier key |
| `secrets.existingSecret` | `""` | set in production; empty renders a warned dev Secret |
| `backup.postgres.enabled` | `true` | resilient-by-default DR tier; disabling is a warned opt-out (no CronJob, archive_command off) |
| `backup.postgres.schedule.full` / `.incr` | `0 1 * * 0` / `0 1 * * 1-6` | weekly-full / daily-incr; each job runs `pgbackrest verify` (gates the job) |
| `backup.postgres.encryption.cipherType` | `aes-256-cbc` | repo encryption, independent of object-store SSE; passphrase by external-secret ref |
| `backup.postgres.repo.endpoint` / `.bucket` / `.prefix` | MinIO svc / `netops-backups` / `/pgbackrest` | object-store repo; credential scoped write-to-`pgbackrest/` only (`pcaps/` is W5-T4) |
| `secrets.keys.backupRepo*` | reference key names | repo cipher pass + S3 key/secret — REFERENCE ONLY, never inlined |
| `serviceAccounts.automountServiceAccountToken` | `false` | workloads need no K8s API token |
| `packet.analysis.*` / `packet.capture.capabilities.add` | full §2 profile / `[NET_RAW,NET_ADMIN]` | NET_RAW only on capture |

## Probes (ADR-0029 §7 / ADR-0015 §4)

`api` liveness `/api/v1/health/live` + readiness `/api/v1/health/ready` :8000;
`worker` celery-ping exec + broker reachability; `frontend` `/healthz` :8080;
data stores native (`pg_isready` / Neo4j / `redis-cli ping`). `api` carries a
`startupProbe` covering slow first boot / Alembic migration.

## Chart-validation + policy-as-test

The chart is gated in CI (`.github/workflows/ci.yml` `infra` job) by:
`helm lint` → `helm template` → `kubeconform -strict` → `kube-linter` →
`conftest test --all-namespaces` (the Rego in `deploy/kubernetes/policy/rego/`
asserts every control above on the rendered manifests) → **Trivy config scan
(gating)** for IaC misconfig. This job is the **G-SEC K8s-posture evidence**
(see `docs/security/2026-06-22-w4-k8s-posture-signoff.md`).

Compose lockstep: `deploy/docker/seccomp/packet-analysis-seccomp.json` is the
byte-for-byte mirror of this chart's profile, wired into the `packet-analysis`
Compose service via `security_opt: ["seccomp=..."]` (ADR-0031 §3).

## P2 carry-forward (not in this chart)

- **HA / scale-out:** HPA, KEDA per-queue workers, CloudNativePG, Redis Sentinel,
  PodDisruptionBudgets (ADR-0029 §1, P2 §3).
- **api→PgBouncer→PG** NetworkPolicy rewrite (P1 is api→PG direct; ADR-0029 §2).
- **cosign enforcement + SBOM** producing pipeline (W6); this chart is the
  admission *enforcement* side only.
