# Kubernetes deployment (production — GA)

Kubernetes is the production deployment target via the **GA** `netops` Helm chart
(ADR-0013 / D13, hardened by ADR-0029). The chart ships in
[`netops/`](netops/README.md); use the
[Docker Compose stack](../docker/README.md) for MVP, dev, and small on-prem
installs, and this chart for the hardened production K8s target.

> **Single-replica, NOT highly available.** P1 GA runs one replica per workload
> with no HPA/operator/PDB — HA is P2 (ADR-0029 §0/§1). See the chart README's
> HA note before treating GA as highly-available.

The chart consumes the same CI-built images as compose (`netops-backend`,
`netops-frontend`), adding orchestration + hardening: per-service
`Deployment`s for `frontend`, `api`, and `worker` (worker queues splittable via
values), toggleable in-chart `StatefulSet`s for the data stores
(`services.postgres.enabled=false` etc. to point at operator-managed or external
instances), liveness/readiness probes wired to `/api/v1/health/live` and
`/api/v1/health/ready`, namespace-wide `restricted` Pod Security Standards with
per-container hardened security contexts, default-deny `NetworkPolicy`s
restricting east-west traffic to the §3.1 topology edges, cert-manager TLS-only
`Ingress`, least-privilege RBAC + Kyverno/VAP admission policy, and
`existingSecret` references so the master key and database credentials never pass
through Helm values in plaintext (ADR-0011, ADR-0013, ADR-0029).

Chart layout:

```
deploy/kubernetes/
├── .kube-linter.yaml                 # static-hardening lint config (infra gate)
├── policy/rego/                      # conftest/OPA policy-as-test (infra gate)
└── netops/                           # GA Helm chart
    ├── Chart.yaml
    ├── values.yaml                   # images, replicas, data-store toggles, existingSecret refs, hardening/admission/networkPolicy seams
    ├── README.md                     # values reference + single-replica/HA note
    ├── seccomp/                      # packet-analysis Localhost seccomp profile (ADR-0031 §3)
    └── templates/
        ├── _helpers.tpl
        ├── NOTES.txt                 # opt-out warnings (secure-by-default)
        ├── configmap.yaml            # NETOPS_* non-secret settings
        ├── secret.yaml               # rendered only when no existingSecret is given (dev convenience)
        ├── serviceaccounts.yaml
        ├── api-deployment.yaml / api-service.yaml
        ├── worker-deployment.yaml    # five restricted queues (no packet)
        ├── frontend-deployment.yaml / frontend-service.yaml
        ├── ingress.yaml / certificate.yaml          # cert-manager TLS, single front door
        ├── networkpolicies.yaml      # default-deny + §3.1 per-edge allows
        ├── namespace.yaml / namespace-packet-capture.yaml   # PSA labels
        ├── postgres-statefulset.yaml # toggleable (external instance supported)
        ├── neo4j-statefulset.yaml    # toggleable
        ├── redis-statefulset.yaml    # toggleable
        ├── ollama-statefulset.yaml   # opt-in (replicas 0 default)
        ├── packet-*.yaml             # ADR-0031 packet-sandbox workloads + policies
        ├── seccomp-installer-daemonset.yaml          # seeds the Localhost profile onto packet nodes
        └── policy/                   # Kyverno ClusterPolicy + ValidatingAdmissionPolicy fallback
```

Chart validation runs in CI (`.github/workflows/ci.yml` `infra` job):
`helm lint` → `helm template` → `kubeconform -strict` → `kube-linter` →
`conftest test --all-namespaces` → Trivy config scan (gating). This is the G-SEC
K8s-posture evidence (`docs/security/2026-06-22-w4-k8s-posture-signoff.md`).
