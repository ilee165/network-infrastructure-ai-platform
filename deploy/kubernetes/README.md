# Kubernetes deployment (production — planned)

Kubernetes is the production deployment target via a Helm chart (ADR-0013 /
D13). The chart lands per [docs/roadmap/PRODUCTION.md](../../docs/roadmap/PRODUCTION.md);
**no manifests ship at M0** — use the [Docker Compose stack](../docker/README.md)
for MVP, dev, and small on-prem installs.

The planned chart consumes the same CI-built images as compose (`netops-backend`,
`netops-frontend`), adding orchestration only: independently scalable
`Deployment`s for `frontend`, `api`, and `worker` (worker replicas splittable
per Celery queue), toggleable in-chart `StatefulSet`s for the data stores
(`postgresql.enabled=false` etc. to point at operator-managed or external
instances), liveness/readiness probes wired to `/api/v1/health/live` and
`/api/v1/health/ready`, non-root pod security contexts, NetworkPolicies
restricting east-west traffic to api/worker -> data stores, TLS ingress, and
`existingSecret` references so the master key and database credentials never
pass through Helm values in plaintext (ADR-0011, ADR-0013).

Planned chart layout:

```
deploy/kubernetes/
└── netops/                            # Helm chart (PRODUCTION.md milestone)
    ├── Chart.yaml
    ├── values.yaml                    # images, replicas, data-store toggles, existingSecret refs
    ├── README.md                      # values reference
    └── templates/
        ├── _helpers.tpl
        ├── configmap.yaml             # NETOPS_* non-secret settings
        ├── secret.yaml                # rendered only when no existingSecret is given
        ├── api-deployment.yaml
        ├── api-service.yaml
        ├── worker-deployment.yaml     # per-queue replica groups via values
        ├── frontend-deployment.yaml
        ├── frontend-service.yaml
        ├── ingress.yaml               # TLS for frontend/api
        ├── networkpolicies.yaml
        ├── postgres-statefulset.yaml  # toggleable (external instance supported)
        ├── neo4j-statefulset.yaml     # toggleable
        └── redis-statefulset.yaml     # toggleable
```
