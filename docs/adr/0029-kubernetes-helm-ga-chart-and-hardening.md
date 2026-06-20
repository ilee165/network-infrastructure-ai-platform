# ADR-0029: Kubernetes/Helm GA Chart and Hardening Round 1

**Status:** Proposed | **Date:** 2026-06-20 | **Milestone:** P1 W0

## Context

CLAUDE.md requires the platform to be **"deployable on-premises using Docker or Kubernetes"** under **"Local first"**, **"Self hosted"**, and **"Secure by default"**. ADR-0013 (D13) fixed the two deployment targets — Docker Compose for MVP/dev, a Helm chart for production — and shipped the Compose stack at M0; the Helm chart was scaffolded as *planned only* (`deploy/kubernetes/README.md`: "no manifests ship at M0"). P1 promotes that planned chart to **GA**: a complete, hardened, installable Helm chart for the production K8s target. PRODUCTION.md schedules this as the P1 platform-orchestration track (§9 K8s hardening round 1, §3.1 service topology), gated by §11.

This ADR is the **design contract** for that chart and the first hardening round; implementation lands in P1 W3/W4 (`wf-infra` owns the declarative half per P1-PLAN.md §2/§3). It **extends ADR-0013 from "planned, convenience-grade" to "GA, hardened-by-default"** and **extends ADR-0015** by binding the probe contract to concrete Helm `livenessProbe`/`readinessProbe` specs. It does not contradict either.

Two scope boundaries are fixed up front, both from PRODUCTION.md and P1-PLAN.md:

- **HA / replica scale-out is EXCLUDED → P2.** PRODUCTION.md §3 (HPA, KEDA, CloudNativePG, Redis Sentinel, PodDisruptionBudgets) is the P2 platform track. The GA chart here ships **single-replica Deployments** with the *structure* to scale later (replica counts in `values.yaml`, stateless `api` per D10) but adds **no** autoscaler, operator, or PDB. ADR-0013's "independently scalable replicas" language is the long-term shape; P1 does not turn it on.
- **The packet-sandbox PSS deviation is owned by ADR-0031, not here.** PRODUCTION.md §9 grants packet workers (D14) a documented `restricted` deviation (`NET_RAW`-capable, non-root, dedicated node pool, own seccomp, default-deny egress). That security-semantic carve-out is defined in **ADR-0031** (packet-sandbox OS-isolation, P1 W3). This ADR **cross-references** it and ensures the chart's namespace-wide `restricted` baseline plus the admission allow-list **accommodate** that one deviation — it does **not** redefine it.

PRODUCTION.md's binding constraint over everything below: **"Helm chart ships hardened defaults — security must be opt-out (with warnings), never opt-in"** (§9 last bullet; CLAUDE.md "Secure by default"). Every default in this chart is the hardened value.

## Decision

**The `deploy/kubernetes/netops/` Helm chart goes GA as a per-service set of `Deployment` + `Service` + `NetworkPolicy` objects derived from the §3.1 topology, with Pod Security Standards `restricted` enforced namespace-wide and every hardening control (readOnlyRootFS, drop-ALL caps, non-root, seccomp `RuntimeDefault`, resource requests/limits, least-privilege RBAC, cert-manager TLS ingress, admission policy) ON by default. Disabling any control requires an explicit `values.yaml` opt-out that emits a Helm `NOTES`/warning. HA scale-out and the packet-sandbox PSS deviation are out of scope (P2 and ADR-0031 respectively).**

### 1. Chart objects derived from the §3.1 topology (P1 GA subset)

PRODUCTION.md §3.1 is the full P2 topology (multi-replica api tier, per-queue KEDA workers, CloudNativePG, Sentinel). The **P1 GA chart renders the single-replica projection** of it. One `Deployment` + `Service` per platform service; data stores stay toggleable in-chart `StatefulSet`s (ADR-0013 §4 — `*.enabled=false` points at external/operator-managed instances, the P2 path).

| Object | Workload | Replicas (P1) | Service | Notes |
|---|---|---|---|---|
| `api-deployment` | `netops-backend` (`uvicorn`) | 1 (values `api.replicas`) | `ClusterIP` :8000 | Stateless (D10 JWT, no server sessions); reached **only** via the `frontend` nginx reverse proxy (ADR-0012 §2), never directly from the ingress controller |
| `worker-deployment` | `netops-backend` (`celery -Q discovery,config,docs,topology,system`) | 1 (values `worker.replicas`) | none (no inbound) | All five `restricted`-compliant queues (`backend/app/workers/celery_app.py`); per-queue split is values-driven. **packet** is the *only* omitted queue — a *separate* workload per ADR-0031, not in this Deployment |
| `frontend-deployment` | `netops-frontend` (nginx) | 1 (values `frontend.replicas`) | `ClusterIP` :8080 | Static Vite output **plus** same-origin reverse proxy for all `/api` + WS traffic (ADR-0012 §2); the **single** ingress target |
| `postgres-statefulset` | `pgvector/pgvector:pg16` | 1 | headless `ClusterIP` :5432 | Toggleable (`postgresql.enabled`); P2 → CloudNativePG |
| `neo4j-statefulset` | `neo4j:5-community` | 1 | `ClusterIP` :7687 | Toggleable; projection, rebuildable (D5) |
| `redis-statefulset` | `redis:7-alpine` | 1 | `ClusterIP` :6379 | Toggleable; P2 → Sentinel |
| `ollama-statefulset` | `ollama/ollama` | 0 (opt-in) | `ClusterIP` :11434 | `ollama.enabled=false` default (ADR-0009 local profile is opt-in here; external provider otherwise) |

The **packet worker** is intentionally absent from `worker-deployment`: ADR-0031 places it on a dedicated node pool with its own pod profile, so the chart references it but its template/NetworkPolicy/PSS deviation are defined there. The `worker-deployment` here carries **every other** queue defined in `backend/app/workers/celery_app.py` — `discovery`, `config`, `docs`, `topology`, and `system` — i.e. all five `restricted`-compliant queues, with `packet` the single deliberate omission. This matters in two concrete ways: (1) the `topology.*` queue (Postgres→Neo4j projection after discovery, M2) has its consumer here, which is what makes the §2 `worker → neo4j` NetworkPolicy edge meaningful — without it Neo4j would stay empty after discovery; (2) `system` is the Celery default queue (`task_default_queue=QUEUE_SYSTEM`) and hosts the `system.healthcheck` broker round-trip that §7's worker readiness "broker reachability" probe relies on, so it cannot be dropped. The dev all-in-one worker in `deploy/docker/docker-compose.yml` additionally folds `packet` into one process (`-Q discovery,config,packet,docs,system`); the GA chart splits `packet` out to its own ADR-0031 workload but keeps the same `topology`/`system` consumers.

Supporting objects: `configmap.yaml` (non-secret `NETOPS_*` settings), `secret.yaml` (rendered **only** when no `existingSecret` is supplied — §6), `serviceaccount.yaml` per workload (§5), `ingress.yaml` (§4), `networkpolicies.yaml` (§2), `_helpers.tpl`, and `policy/` admission manifests (§5).

### 2. NetworkPolicies — default-deny, allows match §3.1 edges only

PRODUCTION.md §9: *"default-deny ingress+egress in all platform namespaces; explicit allows matching the §3.1 topology only; device-management egress confined to the collector namespace."* The chart ships a baseline default-deny plus per-edge allows derived **directly** from the §3.1 flowchart arrows.

- **`default-deny-all`** — selects all pods, denies all ingress and egress. Every other policy is additive. This is the chart's posture floor and is **not** toggleable off without an `networkPolicy.enabled=false` opt-out that prints a warning.
- **DNS egress** — every pod gets egress to `kube-dns` :53 UDP/TCP only (otherwise default-deny breaks name resolution).

Allows (each an explicit `NetworkPolicy`, source → dest, matching a §3.1 arrow):

| From | To | Port | §3.1 edge |
|---|---|---|---|
| `ingress-controller` | `frontend` | 8080 | `LB --> FE` (the **only** ingress front-door edge — nginx in `frontend` reverse-proxies all `/api` + WS traffic per ADR-0012 §2; the ingress controller has **no** direct edge to `api`) |
| `api` | `postgres` | 5432 | `A --> PGB --> PG` (PgBouncer is a P2 insert; P1 is api→PG direct) |
| `api` | `neo4j` | 7687 | `A --> NEO` |
| `api` | `redis` | 6379 | `A --> RED` |
| `worker` | `postgres`, `neo4j`, `redis` | 5432 / 7687 / 6379 | `WD/WC/WX --> {PGB,RED,NEO}` |
| `api`, `worker` | `ollama` (if enabled) | 11434 | `A -. LLM .-> OLL` |
| `frontend` | `api` | 8000 | nginx reverse-proxies `/api` + WebSocket to `api:8000` (ADR-0012 §2); this is the **sole** ingress path to `api`, replacing any direct `ingress-controller → api` edge |

**Device-management egress is NOT granted by this chart.** PRODUCTION.md §5/§9 confine collector egress (workers reaching device SSH/SNMP/HTTPS) to a **dedicated collector namespace/node pool** with egress restricted to management subnets. That collector NetworkPolicy is part of the segmentation work (PRODUCTION.md §5 "collector network segmentation"); the GA platform namespace here gives workers **no** general device egress — a worker that needs device reach is scheduled into the segmented namespace, not granted a blanket allow. External LLM-provider egress (ADR-0009 `anthropic`/`openai`/`azure`) is an **explicit opt-in** allow (`networkPolicy.externalLlmEgress`), default off, since local-first/air-gapped is the default posture (ADR-0015 alt #2).

### 3. Pod hardening — `restricted` PSS, every control ON by default

Namespace gets the three Pod Security Admission labels at **`restricted`**:
`pod-security.kubernetes.io/enforce: restricted`, `.../audit: restricted`, `.../warn: restricted`. The chart's own pod specs are authored to satisfy `restricted` so enforcement is a no-op for compliant pods and a hard block for any future drift.

Per-container `securityContext` defaults (the hardened values — opting out of any is a warned `values.yaml` override):

| Control | Default | PRODUCTION.md / PSS basis |
|---|---|---|
| `runAsNonRoot: true` + `runAsUser`/`runAsGroup` ≥ 1000 | on | §9; ADR-0013 §2 "non-root user" |
| `allowPrivilegeEscalation: false` | on | PSS `restricted` |
| `capabilities.drop: ["ALL"]` (no `add`) | on | §9 "no privileged containers anywhere"; PSS `restricted` |
| `readOnlyRootFilesystem: true` | on | §9; writable `emptyDir` only for declared scratch |
| `seccompProfile.type: RuntimeDefault` | on | PSS `restricted` |
| `privileged: false`, no `hostPath`/`hostNetwork`/`hostPID` | on | §9 |
| resource `requests` + `limits` on every container | on | §9 "on every container" |

**Writable mounts are enumerated, not blanket.** With `readOnlyRootFilesystem: true`, each container declares only the `emptyDir` scratch it needs (e.g. `/tmp`, nginx temp dirs for `frontend`, Ollama model cache `emptyDir` when enabled). The packet worker's pcap scratch is **ADR-0031's** concern, not here (§9 names "pcap scratch, Ollama model cache" as the two writable exceptions). Resource defaults are conservative starting values in `values.yaml` (`api` and `postgres` sized above batch `worker` per §9's PriorityClass intent), tunable per install — but never *absent*.

The single **PSS deviation** in the whole platform is the packet sandbox, and it is **defined by ADR-0031**: `NET_RAW`-capable, still non-root, on its own node pool with its own seccomp profile. This chart's admission allow-list (§5) names exactly that one workload as the permitted deviation; nothing else may deviate.

### 4. Ingress — cert-manager TLS only, no plaintext or NodePort doors

PRODUCTION.md §9: *"Ingress: TLS only, cert-manager-managed certs, HSTS; no NodePort/LoadBalancer side doors."*

- One `Ingress` (default class, values-overridable) routing **all** paths (`/`) to the `frontend` Service over **HTTPS only**. Per the binding ADR-0012 §2 decision, nginx inside the `frontend` container is the **same-origin reverse proxy** for all `/api` REST and `/ws` WebSocket (agent-session) traffic — the ingress does **not** route `/api` to the `api` Service directly. This is deliberate: keeping API + WebSocket same-origin behind nginx eliminates the cross-origin (CORS) surface as a secure-by-default property (ADR-0012 §2), so the chart **must not** reintroduce a direct ingress→api door. The WebSocket upgrade for agent sessions (ADR-0015 §3) is handled by nginx's proxy, not a second ingress backend.
- **cert-manager** issues the cert: the chart renders a `Certificate` referencing a `ClusterIssuer`/`Issuer` named in values (`ingress.tls.issuerRef`); the resulting `Secret` (the TLS keypair) is **cert-manager-managed**, never templated from Helm values. No certificate private key ever appears in `values.yaml`.
- `ssl-redirect: true` and **HSTS** response header are default annotations; plaintext :80 only 308-redirects to :443.
- All platform `Service`s are `ClusterIP`. The chart exposes **no** `NodePort` or `LoadBalancer` Service — the ingress controller is the single, TLS-terminated front door. A `service.type` override away from `ClusterIP` is a warned opt-out.

### 5. Least-privilege RBAC and admission policy

**ServiceAccounts (§9 "no cluster-scope permissions; `automountServiceAccountToken: false` where unused").** Each workload (`api`, `worker`, `frontend`) gets its **own** ServiceAccount; none is granted any `Role`/`ClusterRole` by default — the platform talks to Postgres/Neo4j/Redis, **not** the K8s API, so it needs **no** K8s RBAC at all in the steady state. `automountServiceAccountToken: false` on every pod spec by default. The chart ships **zero** `ClusterRoleBinding`. The only namespaced `Role` is a tightly-scoped one for the Helm **pre-upgrade migration Job** (PRODUCTION.md §10 expand/contract Alembic Job) if it needs to read its own ConfigMap — and that is opt-in with the migration hook, not granted to long-running pods.

**Admission policy (§9 "Kyverno or ValidatingAdmissionPolicy: require signed images, disallow `latest` tags, enforce PSS deviations allow-list").** The chart ships admission manifests under `templates/policy/`, default-enabled, implementing three rules:

1. **No `latest` / no mutable tags** — every image must be a digest-pinned or explicit-version reference (parity with PRODUCTION.md §10 "LLM model tags pinned in the release manifest" and D13's released-as-a-set images).
2. **Signed-image verification** — images must carry a valid **cosign** signature (the §5 supply-chain control; the verifying key/identity is a values input). This pairs with the W6 SBOM/cosign CI work — the chart is the *enforcement* side of that pipeline.
3. **PSS-deviation allow-list** — the *only* workload permitted to carry `NET_RAW` / a non-default seccomp profile is the **ADR-0031 packet sandbox**, matched by an explicit label selector; every other pod must satisfy `restricted`. This is the chart-side guard that ADR-0031's deviation cannot silently spread.

**PROPOSED engine choice: Kyverno** (declarative `ClusterPolicy`, ships its own cosign image-verification, conftest/OPA-testable in CI per `wf-infra`'s gate set) with a `ValidatingAdmissionPolicy` fallback for clusters that forbid an admission webhook. Either way the policy is a chart artifact, version-locked to the release, and the admission rules are **on by default** — `admissionPolicy.enabled=false` is a warned opt-out for clusters running an external org-wide policy engine.

### 6. Secrets posture — no device credentials in K8s, platform secrets by reference

PRODUCTION.md §9: *"no Kubernetes Secret holds device credentials (they live AES-256-GCM-encrypted in Postgres per D11); platform secrets via external-secrets operator or CSI secrets store backed by the customer KMS/Vault."* This ADR holds that line and matches the ADR-0011 / ADR-0024 §2 posture: **credential material is referenced indirectly, never inlined.**

- **Device credentials never become K8s objects.** They stay envelope-encrypted in Postgres (D11). No chart template ever renders a device-credential Secret. This is structural, not configurable.
- **Platform secrets** (DB password, master-key reference per D11, OIDC client secret per ADR §4) are supplied by **`existingSecret` reference** (ADR-0013 §4) — the chart's `secret.yaml` renders **only** when no `existingSecret` is given (a dev convenience that prints a warning recommending external-secrets in production). The **PROPOSED** production path is the **external-secrets operator** or a **CSI secrets-store** volume backed by the customer KMS/Vault (the D11 KMS-compatible interface; the W6 KMS work feeds this). No secret value passes through `values.yaml` or Helm release history in plaintext.
- The **master key is a *reference*, not a value** — the pod receives a KMS handle / mounted secret path, consistent with PRODUCTION.md §5 "master key moved from env/file to a real KMS". No KEK, token, or password literal appears in any template, value, log line, or this ADR.

### 7. Probe contract (extends ADR-0015 §4)

ADR-0015 §4 defined the health/readiness endpoints; this chart binds them to concrete probe specs (the `deploy/kubernetes/README.md` paths `/api/v1/health/live` and `/api/v1/health/ready` are the canonical paths):

| Workload | livenessProbe | readinessProbe |
|---|---|---|
| `api` | `httpGet /api/v1/health/live` :8000 | `httpGet /api/v1/health/ready` :8000 (checks PG/Redis/Neo4j; failing pulls pod from the Service, doesn't kill it — ADR-0015 §4) |
| `worker` | `exec` celery ping script (ADR-0015 §4 PROPOSED) | same script + broker reachability |
| `frontend` | `httpGet /healthz` :8080 (nginx static 200) | same |
| `postgres`/`neo4j`/`redis` | native (`pg_isready` / Neo4j HTTP / `redis-cli ping`) | native |

Probes are **on by default** with conservative `initialDelaySeconds`/`periodSeconds` in values; readiness gating is what makes the §1 single-replica `api` roll safely under the §10 rolling-upgrade order (`startupProbe` covers slow first boot / migration wait).

## Consequences

**Positive**
- The chart is **secure-by-default in the strong sense**: `restricted` PSS, drop-ALL caps, readOnlyRootFS, non-root, seccomp, default-deny NetworkPolicies, TLS-only ingress, and signed-image admission are all the *default* — an operator must consciously, visibly opt out (with a Helm warning) to weaken any of them. This directly satisfies the CLAUDE.md / PRODUCTION.md §9 "opt-out never opt-in" mandate and gives G-SEC its K8s-posture evidence.
- It extends ADR-0013 to GA without contradiction: same images, same toggleable data stores, same `existingSecret` posture — only orchestration and hardening are added, exactly as D13 framed the Helm chart's role.
- NetworkPolicies derived edge-for-edge from §3.1 mean the topology diagram **is** the firewall spec — review and drift-detection have a single source of truth, and device-management egress is structurally confined to the collector namespace (no blanket worker egress).
- Excluding HA keeps P1 shippable and reviewable; the chart's values structure (replica counts, data-store toggles) is the seam P2 widens (HPA/KEDA/operators) with no template rewrite.
- The admission allow-list makes ADR-0031's single PSS deviation **enforceably singular** — the packet sandbox cannot leak its privilege to any other workload, and signed-image + no-`latest` enforcement closes the chart-side of the W6 supply-chain pipeline.

**Negative**
- Hardened-by-default raises the bar for *running* the chart: clusters without cert-manager, an ingress controller, and a policy engine (Kyverno) need those prerequisites, and air-gapped installs must mirror those too — documented as chart dependencies, but real install friction (mitigated by the warned opt-outs for clusters with org-wide equivalents).
- `readOnlyRootFilesystem: true` everywhere forces every writable path to be enumerated as an `emptyDir`; a missed scratch dir surfaces only at runtime (a third-party image that writes to `/var/run`), so the chart needs per-image write-path tests in CI (`wf-infra` policy-as-test).
- Single-replica P1 means **no in-cluster HA** — a node loss takes a service down until reschedule; this is an accepted P1 limitation (HA is P2 §3) and must be stated plainly in the chart README so no one mistakes GA for highly-available.
- Two NetworkPolicy realities (the P1 api→PG-direct edge vs. the P2 api→PgBouncer→PG edge) mean the policy set changes when P2 inserts PgBouncer/Sentinel — a known, scheduled edit, not silent drift.
- Keeping the Helm chart and the Compose stack in lockstep (ADR-0013 negative) now also spans the hardening surface; a new env var or volume is a two-place change plus a policy review.

## Alternatives considered

1. **Ship the chart with hardening as opt-in flags (default-permissive, `hardened=true` to enable).** **Rejected** — directly violates PRODUCTION.md §9's last bullet and CLAUDE.md "Secure by default". A default-permissive chart that an operator forgets to harden is the exact failure mode the mandate exists to prevent; the inversion (hardened default, warned opt-out) is non-negotiable and is the chosen posture throughout.
2. **Enforce PSS `baseline` (not `restricted`) namespace-wide.** **Rejected** — `baseline` permits `runAsRoot`, retained capabilities, and writable root filesystems, none of which any platform workload needs. `restricted` is achievable for every P1 service (verified against the container set), so accepting a weaker profile would forfeit free hardening; the one workload that genuinely needs more (`NET_RAW` packet sandbox) is handled as a named, admission-gated deviation (ADR-0031), not by lowering the floor for everyone.
3. **Bundle HA (HPA + KEDA + CloudNativePG + Sentinel + PDBs) into the P1 GA chart.** **Rejected for P1** — PRODUCTION.md explicitly schedules HA/scale-out as the **P2** platform track (§3); pulling it forward couples the GA-chart milestone to operator dependencies and autoscaler tuning that P1 isn't gated on (G-SCA is a P2/later gate). The chart is built with the values seams (replicas, toggles) so P2 layers HA on without a rewrite. **Chosen:** single-replica GA now, HA in P2.
4. **No admission engine — rely on PSA labels alone for policy.** **Rejected** — Pod Security Admission enforces the PSS profile but **cannot** require signed images, ban `latest` tags, or express a per-workload deviation allow-list, all three of which PRODUCTION.md §9 names. A policy engine (Kyverno / VAP) is required for the supply-chain and deviation-allow-list rules; PSA labels remain the baseline and the policy engine adds the rest. **Chosen:** PSA labels **and** an admission policy, default-enabled.
5. **Define the packet-sandbox pod profile and its PSS deviation in this ADR (one K8s-security ADR).** **Rejected** — the sandbox is a security-semantic, OS-isolation concern (`NET_RAW`, dedicated node pool, seccomp profile, default-deny device egress) scoped to P1 W3 and owned by `wf-infra` under **ADR-0031**. Duplicating it here would create two sources of truth for one deviation and risk drift between the profile and the admission allow-list that gates it. **Chosen:** ADR-0031 defines the deviation; this ADR's admission allow-list (§5) references and enforces it singularly.
6. **Render TLS certs from Helm values / a chart-managed self-signed Secret instead of cert-manager.** **Rejected** — PRODUCTION.md §9 names cert-manager explicitly; templating a keypair through `values.yaml` would put private-key material in Helm release history (violating the ADR-0011 / §6 no-secrets-in-values posture). cert-manager owns issuance and rotation; the chart only references the issuer. **Chosen:** cert-manager-managed `Certificate`, default on.
