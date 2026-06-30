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

- **cert-manager** (REQUIRED by default) — it issues BOTH the TLS Ingress cert
  (`ingress.tls.issuerRef`) AND, since PR#76, the api/worker/cronjob ↔ Postgres
  **DB-link mTLS** cert material (`mtls.postgres.enabled=true` is now the secure
  default; the chart renders the bootstrap self-signed Issuer → DB CA → server +
  client `Certificate` CRs that cert-manager provisions + auto-rotates). No key
  material ever passes through Helm values. If cert-manager is not installed you
  must either run the self-signed dev/CI fallback
  (`mtls.postgres.certManager.enabled=false`, NOT for production) or take the
  documented opt-out (`mtls.postgres.enabled=false`, a warned plaintext DB link).
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

### External Postgres + mTLS

When the DB is **external** (`services.postgres.enabled=false`) the chart renders
**no in-chart Postgres server** — no server `Certificate`, no `pg_hba` ConfigMap,
no StatefulSet `ssl=on`/`hba_file` wiring. But with `mtls.postgres.enabled=true`
the api/worker/cronjobs **still** get `verify-full` mTLS **client** config
(`NETOPS_DB_SSL_*` + the client cert mount) pointed at that external host. If the
external server was never configured for the same mutual TLS, every client dials a
server that does not offer mTLS — a **silently broken** deploy.

To prevent that, the chart **fails the render** when
`mtls.postgres.enabled=true` **and** `services.postgres.enabled=false` **unless**
you set `mtls.postgres.external.enabled=true`. Before setting it, provision the
external server's mTLS **out-of-band**:

1. the external Postgres presents a **server cert** whose CA the client trusts —
   mount the matching `ca.crt` into `clientSecretName`/`caSecretName` (or point the
   client Secret at your own CA material);
2. the external server's `pg_hba` requires
   `hostssl … scram-sha-256 clientcert=verify-full` (no weaker/plaintext row — the
   same posture the in-chart `pg_hba` ConfigMap encodes, asserted by the
   `netops.hardening` pg_hba policy);
3. `config.postgres.host` points at the external host and the client cert CN
   (`mtls.postgres.clientCommonName`) equals `config.postgres.user`
   (`clientcert=verify-full` checks `CN == username`).

Alternatively set `mtls.postgres.enabled=false` for a plaintext
(NetworkPolicy-isolated) DB link (a warned opt-out). (ADR-0039 §3/§4; M8/PR#76
round-2 #25.)

## Key values

| Key | Default | Notes |
|---|---|---|
| `services.<svc>.replicas` | `1` | SINGLE-REPLICA static seam; for `api` it is unused while the HPA is on (autoscaling owns the count). Raising it elsewhere is a warned HA seam |
| `services.<svc>.enabled` | `true` (ollama `false`) | data stores toggleable to external/operator-managed |
| `services.<svc>.type` | `ClusterIP` | NodePort/LoadBalancer is a warned opt-out (Ingress is the single front door) |
| `services.api.autoscaling.enabled` | `true` | api HorizontalPodAutoscaler (W2-T1, ADR-0043 §1). ON by default (resilient-by-default); disabling reverts to the static `replicas` seam (warned, not HA) |
| `services.api.autoscaling.minReplicas` | `2` | FLOOR >=2 ALWAYS (PRODUCTION.md §3.2); the render REFUSES `< 2` (a floor of 1 cannot survive a node loss and defeats the PDB) |
| `services.api.autoscaling.maxReplicas` | `10` | PROPOSED ceiling (ADR-0043 §1; the §327 "linear at 4 replicas" sets the practical lower bound) |
| `services.api.autoscaling.cpu.targetUtilizationPercent` | `70` | CPU-utilization signal (% of the api CPU request — meaningless without requests) |
| `services.api.autoscaling.requestRate.enabled` / `.metricName` | `true` / `http_requests_per_second` | per-pod request-rate signal (ADR-0043 §1). Metric is published by the api `/metrics` via a Prometheus adapter — **W3 (observability) scope**, referenced by canonical name only here (no new instrumentation). Set `enabled:false` on a cluster with no adapter |
| `services.api.autoscaling.requestRate.targetAverageValue` | `"50"` | target req/sec/pod (PROPOSED; tuned in the W4-T6 load drill) |
| `services.api.autoscaling.behavior.{scaleUp,scaleDown}` | 30s up / 300s down windows | stabilization windows (fast scale-out, anti-flap scale-in; ADR-0043 §1/§2) |
| `services.api.podDisruptionBudget.enabled` / `.minAvailable` | `true` / `1` | api PDB (W2-T1, ADR-0043 §1; PRODUCTION.md §3.2) — a node drain never takes api to zero. ON by default; disabling is warned |
| `hardening.securityContext.*` | hardened | reusable per-container context (every workload consumes the `netops.hardenedSecurityContext` helper) |
| `namespaceLabels.podSecurity.enforce` | `restricted` | weakening is a warned opt-out |
| `ingress.enabled` / `ingress.host` | `true` / placeholder | set `host` to your real FQDN |
| `ingress.tls.certManager.enabled` / `issuerRef` | `true` / placeholder | cert-manager issues the TLS Secret; no key in values |
| `mtls.postgres.enabled` | `true` | DB-link mutual TLS ON by default (ADR-0039); needs cert-manager (or the dev fallback). Disabling is a warned plaintext opt-out |
| `mtls.postgres.certManager.enabled` | `true` | cert-manager issues + auto-rotates the DB cert material; `false` = self-signed dev/CI fallback (not for production) |
| `mtls.postgres.certManager.caDuration` / `duration` | `87600h` / `2160h` | the CA outlives the leaves by ~40x so CA rotation is rare/planned (M5) |
| `mtls.postgres.external.enabled` | `false` | attest the EXTERNAL Postgres (`services.postgres.enabled=false`) has mTLS provisioned out-of-band. REQUIRED when `mtls.postgres.enabled=true` AND `services.postgres.enabled=false`, else the render FAILS fast (see "External Postgres + mTLS") |
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
| `cloudNativePg.enabled` | `false` | OPT-IN CloudNativePG HA tier (W1-T1, ADR-0042). Mutually exclusive with `services.postgres.enabled` (render REFUSES both). Requires the CNPG operator pre-installed |
| `cloudNativePg.instances` | `3` | 1 primary + 2 streaming replicas (the ANY 1 quorum + failover-quorum minimum) |
| `cloudNativePg.synchronous.{method,number,failoverQuorum}` | `any` / `1` / `true` | QUORUM sync `ANY 1 (replicas)` for the audit write path (ADR-0042 §2). NOT forced on all writes — W1-T2 scopes it per-transaction via `SET LOCAL` |
| `cloudNativePg.pgbouncer.poolMode` | `transaction` | PgBouncer transaction-mode pooling (the connection budget + audit `SET LOCAL` correctness; ADR-0042 §4). `session`/`statement` are policy-rejected |
| `cloudNativePg.pgbouncer.{maxClientConn,defaultPoolSize}` | `1000` / `25` | connection budget (G-SCA §330): large client ceiling multiplexed onto a small server-side pool |
| `cloudNativePg.priorityClass.{create,name,value}` | `true` / `netops-postgres-ha` / `1000000` | PriorityClass so Postgres outranks the unpriorited batch workers under node pressure |
| `cloudNativePg.pgvectorReplicaSmoke.enabled` | `true` | renders the pgvector-on-replica smoke Job (ADR-0042 §5); the LIVE query is the W4-T1 kind drill (rendered emulation locally) |
| `cloudNativePg.backup.enabled` | `true` | CNPG WAL/base-backup archiving to the same object store as the pgBackRest tier (ADR-0030), credentials by-reference |
| `secrets.keys.cnpg*` | reference key names | CNPG superuser/app basic-auth passwords — dev path `lookup` reuse-or-generate (L4, never regenerated); production via existingSecret |
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
(gating)** for IaC misconfig. The api HPA + PDB (W2-T1, ADR-0043) render BY
DEFAULT, so they are covered by the default-render conftest/kubeconform/kube-linter
gates above and additionally by the **api HPA + PDB BITE**
(`deploy/kubernetes/policy/fixtures/run-api-hpa-pdb-bite.sh` — floor>=2 + CPU+
request-rate dual signal + PDB minAvailable>=1). The opt-in CloudNativePG HA tier (ADR-0042) is
additionally rendered with `cloudNativePg.enabled=true` and gated by the same
kubeconform/kube-linter/conftest set, the **cnpg sync-quorum + pooler-budget BITE**
(`deploy/kubernetes/policy/fixtures/run-cnpg-bite.sh`) and the **CNPG render-twice
L4 guard** (`ci/cnpg/render-twice.sh`). This job is the **G-SEC K8s-posture
evidence** (see `docs/security/2026-06-22-w4-k8s-posture-signoff.md`).

Compose lockstep: `deploy/docker/seccomp/packet-analysis-seccomp.json` is the
byte-for-byte mirror of this chart's profile, wired into the `packet-analysis`
Compose service via `security_opt: ["seccomp=..."]` (ADR-0031 §3).

## CloudNativePG HA data tier (W1-T1, ADR-0042)

OPT-IN (`cloudNativePg.enabled=true`, default OFF). Replaces the single-instance
`services.postgres` StatefulSet (set `services.postgres.enabled=false` — the chart
REFUSES to render both Postgres tiers) with a CloudNativePG `Cluster` of 1 primary
+ 2 streaming replicas, a PgBouncer `Pooler` (transaction mode), a PriorityClass so
Postgres outranks batch workers, and **quorum synchronous replication scoped to the
audit write path** (`synchronous: {method: any, number: 1, failoverQuorum: true}` =
`ANY 1 (replicas)`). It does NOT force synchronous commit on all writes: the cluster
default `synchronous_commit` is set EXPLICITLY to `local` (ADR-0042 §2) so non-audit
writes ack locally — leaving it unset would inherit the PG default `on` and force the
quorum round-trip onto every write — and W1-T2 raises it back per-transaction via
`SET LOCAL synchronous_commit=remote_apply` on the audit-writing transaction.
pgvector is installed at bootstrap (inherited by replicas) and verified queryable on
a replica by the smoke Job. Requires the CloudNativePG operator (CRDs + controller)
pre-installed. mTLS to the CNPG cluster + app-side read/write routing are W1-T2; the
live failover / zero-audit-loss drill is W4-T3.

CNPG superuser/replication passwords use the same `lookup` reuse-or-generate dev
fallback as the platform Secret (L4 — never regenerated on upgrade); production
supplies them via `secrets.existingSecret` / external-secrets. The HA render is
gated in CI (render + kubeconform + kube-linter + conftest + the cnpg sync-quorum/
pooler-budget BITE + the CNPG render-twice L4 guard).

## P2 carry-forward (not in this chart)

- **HA / scale-out:** HPA, KEDA per-queue workers, Redis Sentinel,
  PodDisruptionBudgets (ADR-0029 §1, P2 §3). CloudNativePG (Postgres HA) is now in
  this chart as the opt-in tier above (W1-T1, ADR-0042).
- **api→PgBouncer→PG** NetworkPolicy rewrite (P1 is api→PG direct; ADR-0029 §2).
- **cosign enforcement + SBOM** producing pipeline (W6); this chart is the
  admission *enforcement* side only.
