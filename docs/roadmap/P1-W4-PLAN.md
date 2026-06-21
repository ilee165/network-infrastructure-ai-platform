# P1 W4 Build-Plan Note — Helm / K8s GA Chart

**Wave:** P1 W4 (Helm / K8s GA chart) — `docs/roadmap/P1-PLAN.md` §3 row W4.
**Design contract:** `docs/adr/0029-kubernetes-helm-ga-chart-and-hardening.md` (GA chart + hardening round 1).
**Status:** Planned. Entry condition: W3 (packet-sandbox OS-isolation, ADR-0031) provides the named PSS deviation this chart's admission allow-list references — see §6 Sequencing.
**Authority:** Bound by `CLAUDE.md`, `docs/roadmap/PRODUCTION.md` §9 / §3.1, ADR-0013 (D13), ADR-0012 §2, ADR-0015 §4, and the cross-referenced ADR-0031 (packet sandbox) / ADR-0028 (OIDC client secret) / ADR-0032 (KMS).
**Binding constraint (from ADR-0029 / PRODUCTION.md §9):** *secure-by-default = opt-out (with a Helm warning), never opt-in.* Every default rendered by this chart is the hardened value.

---

## 1. Scope

In scope (P1 GA subset, ADR-0029 Decision):

- Per-service `Deployment` + `Service` for `api`, `worker`, `frontend`; toggleable `StatefulSet`s for `postgres`/`neo4j`/`redis`/`ollama` (§1 topology table).
- `restricted` Pod Security Standards enforced namespace-wide; every per-container hardening control ON by default (§3).
- Default-deny `NetworkPolicy` baseline + per-edge allows derived edge-for-edge from PRODUCTION.md §3.1 (§2).
- cert-manager TLS-only `Ingress` → `frontend` (single front door; ADR-0012 §2 same-origin nginx proxy) (§4).
- Least-privilege RBAC (per-workload ServiceAccounts, zero `ClusterRoleBinding`) + admission policy (no-`latest`, signed-image, PSS-deviation allow-list) (§5).
- Secret-by-reference posture: `existingSecret`, no credential material in values/release history (§6).
- Probe contract bound to ADR-0015 §4 canonical paths (§7).
- Chart-validation CI gates (helm lint, kubeconform, kube-linter, conftest/OPA policy-as-test).

Explicitly OUT of scope (do not pull forward):

- **HA / replica scale-out → P2** (HPA, KEDA, CloudNativePG, Sentinel, PDBs). Chart ships single-replica with the *values seams* to scale, no autoscaler/operator/PDB (ADR-0029 §1, Alt #3).
- **Packet-sandbox pod profile + its PSS deviation → ADR-0031 / W3.** This chart only *references and enforces* that one deviation via its admission allow-list (ADR-0029 §3/§5, Alt #5).
- **cosign signing + SBOM (syft) + trivy/dep/secret-scan CI pipeline → W6.** This chart is the *enforcement* (admission) side; the *producing* pipeline is W6 (ADR-0029 §5 rule 2).
- **PgBouncer / Sentinel topology edges → P2.** P1 NetworkPolicies encode the api→PG-direct edge; the api→PgBouncer→PG rewrite is a scheduled P2 edit (ADR-0029 §2, Consequences).

---

## 2. Task decomposition

Per-task workflow pattern (P1-PLAN §3): **1 implementer → 2 parallel reviewers (spec + quality) → conditional fixer → verifier → 1 atomic commit.** Tasks are dependency-ordered and **sequential** because they share the chart's `values.yaml` and `_helpers.tpl` (P1-PLAN §3: parallelize only the two reviews within a task, never file-sharing tasks). ADRs land from W0; no new ADR in W4.

| Task | Deliverable | Owner | Depends on |
|---|---|---|---|
| **W4-T1 — Chart skeleton + hardened-default values** | `Chart.yaml`, `values.yaml` (replica counts, data-store toggles, per-container `securityContext` defaults, resource req/limits, `existingSecret` ref, all opt-out flags), `_helpers.tpl`, `configmap.yaml`, `secret.yaml` (renders only when no `existingSecret`), `NOTES.txt` (opt-out warnings). Establishes the secure-by-default value contract every later task references. | `wf-infra` (strong) | W0 ADR-0029 |
| **W4-T2 — Workload manifests** | `api-deployment`/`api-service`, `worker-deployment` (5 `restricted` queues: `discovery,config,docs,topology,system`; **no** `packet` — ADR-0029 §1), `frontend-deployment`/`frontend-service`, toggleable `postgres`/`neo4j`/`redis`/`ollama` StatefulSets. Per-container `securityContext` from `_helpers`, enumerated `emptyDir` writable mounts (readOnlyRootFS), resource req/limits, probes (§7). Boilerplate mirroring ADR-0029 §1 table. | `wf-implementer-light` (sonnet) | T1 |
| **W4-T3 — NetworkPolicies** | `networkpolicies.yaml`: `default-deny-all`, DNS egress to kube-dns :53, per-edge allows from ADR-0029 §2 table (ingress→frontend, frontend→api, api→{pg,neo4j,redis}, worker→{pg,neo4j,redis}, api/worker→ollama if enabled), `externalLlmEgress` opt-in (default off). No blanket device egress. | `wf-infra` (strong) | T2 (selectors match workload labels) |
| **W4-T4 — Ingress + TLS** | `ingress.yaml`: single HTTPS-only Ingress, all paths → `frontend` (no direct →api door, ADR-0012 §2); cert-manager `Certificate` referencing `ingress.tls.issuerRef`; `ssl-redirect`+HSTS annotations; ClusterIP-only (warned opt-out on `service.type`). | `wf-infra` (strong) | T1, T2 |
| **W4-T5 — RBAC + admission policy** | Per-workload ServiceAccounts (`automountServiceAccountToken: false`), zero `ClusterRoleBinding`, opt-in migration-Job `Role`; PSS namespace labels (`enforce/audit/warn: restricted`); `templates/policy/` Kyverno `ClusterPolicy` set (no-`latest`, cosign signed-image verify, PSS-deviation allow-list naming **only** the ADR-0031 packet sandbox) + `ValidatingAdmissionPolicy` fallback. | `wf-infra` (strong) | T2 (workload labels), ADR-0031 (W3) for the deviation selector |
| **W4-T6 — Chart-validation CI + policy-as-test** | Wire `helm lint`, `kubeconform`, `kube-linter`/kubescape, and `conftest`/OPA unit tests (assert default-deny present, every edge allow matches a §3.1 arrow, admission allow-list names exactly one workload, readOnlyRootFS write-path coverage) into CI. **Excludes** cosign/SBOM/trivy (W6). Produces the G-SEC K8s-posture evidence artifact. | `wf-infra` (strong) | T1–T5 |

Reviewer escalation (ADR-0029 §3 watch + P1-PLAN §2 escalation rule): **every W4 task gets strong-tier spec + quality review** — the whole chart is security-semantic YAML (NetworkPolicy / PSS / admission / secret-surface). No W4 review runs on a downgraded model.

---

## 3. File targets

All under `deploy/kubernetes/netops/` (layout pre-declared in `deploy/kubernetes/README.md`):

```
deploy/kubernetes/netops/
├── Chart.yaml                              # T1
├── values.yaml                             # T1 (later tasks append keys, sequentially)
├── README.md                               # T6 — values reference; MUST state single-replica/non-HA plainly
└── templates/
    ├── _helpers.tpl                        # T1
    ├── NOTES.txt                           # T1 — opt-out warnings
    ├── configmap.yaml                      # T1  (NETOPS_* non-secret settings)
    ├── secret.yaml                         # T1  (renders only when no existingSecret)
    ├── serviceaccount.yaml                 # T5
    ├── api-deployment.yaml                 # T2
    ├── api-service.yaml                    # T2
    ├── worker-deployment.yaml              # T2  (no packet queue)
    ├── frontend-deployment.yaml            # T2
    ├── frontend-service.yaml               # T2
    ├── postgres-statefulset.yaml           # T2  (toggleable)
    ├── neo4j-statefulset.yaml              # T2  (toggleable)
    ├── redis-statefulset.yaml              # T2  (toggleable)
    ├── ollama-statefulset.yaml             # T2  (opt-in, replicas 0 default)
    ├── ingress.yaml                        # T4
    ├── certificate.yaml                    # T4  (cert-manager Certificate)
    ├── networkpolicies.yaml                # T3
    ├── namespace.yaml / ns PSS labels      # T5  (restricted enforce/audit/warn)
    └── policy/                             # T5  (Kyverno ClusterPolicy + VAP fallback)
        ├── disallow-latest-tag.yaml
        ├── verify-image-signature.yaml
        └── pss-deviation-allowlist.yaml
```

CI / tests (T6):

```
.github/workflows/             # add chart-validation job(s): helm lint, kubeconform, kube-linter, conftest
deploy/kubernetes/netops/tests/  # conftest/OPA rego policy unit tests + helm-unittest assertions
docs/roadmap/                  # G-SEC K8s-posture evidence note (or append to gate-evidence doc)
deploy/kubernetes/README.md    # update "planned" → GA, drop the "no manifests ship" note
```

---

## 4. Agent / model assignment

| Agent | Model | W4 tasks | Rationale |
|---|---|---|---|
| `wf-infra` | strong (inherit) | T1, T3, T4, T5, T6 | Declarative infra/CI with security-semantic YAML (NetworkPolicy/PSS/admission/secret-by-reference/TLS) + infra gates, not Python-TDD (P1-PLAN §2; `.claude/agents/README.md`). |
| `wf-implementer-light` | sonnet | T2 | Boilerplate Deployment/Service/StatefulSet manifests mirroring the ADR-0029 §1 table — template-following, no novel security design. |
| `wf-spec-reviewer` | **strong (`fable`)** | every task | Security-semantic chart → escalated (ADR-0029 §3 watch, README escalation rule). |
| `wf-quality-reviewer` | **strong (`fable`)** | every task | Secret-surface + NetworkPolicy/PSS/admission semantics → escalated. |
| `wf-fixer` | sonnet | conditional | Applies enumerated review findings only. |
| `wf-verifier` | sonnet | per fixed task | Confirms the fix commit resolves findings. |

No new agent definition required — `wf-infra` was created at P1-PLAN §2 to own exactly this declarative half of W3–W6.

---

## 5. Gates

Infra gate set (`wf-infra` discipline, not Python-TDD) run per task before its atomic commit, and consolidated in T6:

| Gate | Check | Pass condition |
|---|---|---|
| `helm lint` | chart renders & lints clean | 0 errors |
| `kubeconform` | rendered manifests schema-valid against target K8s version | all objects valid |
| `kube-linter` / kubescape | static hardening posture | no findings on readOnlyRootFS, runAsNonRoot, drop-ALL caps, resource limits, seccomp |
| `conftest` / OPA (policy-as-test) | rego unit tests over rendered output | default-deny present; every NetworkPolicy allow maps to a §3.1 edge; admission allow-list names exactly one workload (packet sandbox); no `latest` tags; no inlined secret values |
| helm-unittest | template assertions | securityContext defaults present on every container; `existingSecret` path renders no `secret.yaml`; opt-out flags emit NOTES warnings |
| Gate mapping (PRODUCTION.md §11) | — | **G-SEC** (K8s-posture evidence — primary), **G-OBS** (probes wired), **G-MNT** (chart lint/maintainability); **G-SCA** *enforcement side only* (admission no-`latest`/signed-image) — producing pipeline is W6. |

Out-of-band (W6, referenced not run here): cosign verify, SBOM (syft), trivy image scan, gitleaks.

---

## 6. Sequencing

- **Predecessor:** W3 must land first — ADR-0031 defines the packet-sandbox PSS deviation (label selector + seccomp profile) that T5's admission allow-list names. Without it the allow-list has nothing valid to reference (P1-PLAN §4 "W3 → W4 ordered: sandbox profile feeds the chart's PSS deviation").
- **Internal order:** T1 → T2 → {T3, T4, T5 sequential, all append to `values.yaml`/`_helpers.tpl`} → T6. Within each task, the two reviews run in parallel; tasks themselves are sequential (shared chart files).
- **Successors:** W5 (backup/DR) and W6 (security hardening) depend on W4 — they need the chart's deploy targets and namespaces (P1-PLAN §4 "W5, W6 after W4").
- **Cross-references consumed:** ADR-0028 (OIDC client secret → `existingSecret` key in T1), ADR-0032 (KMS master-key reference → T1/T6 secret posture), ADR-0012 §2 (same-origin proxy → T4 no direct →api door), ADR-0015 §4 (probe paths → T2/T7).

---

## 7. Exit criteria

W4 is complete when **all** hold on the wave HEAD:

1. **Secure-by-default verified:** `restricted` PSS namespace-wide; per-container `runAsNonRoot`, `allowPrivilegeEscalation: false`, drop-ALL caps, `readOnlyRootFilesystem: true`, seccomp `RuntimeDefault`, resource req+limits — all ON by default; disabling any requires a `values.yaml` opt-out that emits a Helm warning (ADR-0029 §3, Alt #1). No control is opt-in.
2. **NetworkPolicies are the firewall spec:** `default-deny-all` present; every allow maps edge-for-edge to a PRODUCTION.md §3.1 arrow (ADR-0029 §2 table); no blanket device-management egress; external-LLM egress is opt-in default-off. Verified by conftest.
3. **Ingress TLS-only:** single HTTPS Ingress → `frontend` only; cert-manager `Certificate` (no key in values); HSTS + ssl-redirect; all Services `ClusterIP`, zero NodePort/LoadBalancer (ADR-0029 §4).
4. **Admission allow-list singular:** Kyverno (`+ VAP fallback`) enforces no-`latest`, signed-image, and a PSS-deviation allow-list naming **exactly** the ADR-0031 packet sandbox; conftest asserts cardinality = 1 (ADR-0029 §5).
5. **Secrets by reference only:** no device credential ever a K8s object; `secret.yaml` renders only without `existingSecret`; no credential/master-key/OIDC-secret literal in any template, value, log, or release history (ADR-0029 §6).
6. **Probes bound:** liveness/readiness on every workload per ADR-0029 §7 (api `/api/v1/health/live` + `/ready`; worker celery ping + broker; frontend `/healthz`; data stores native); startupProbe covers slow first boot/migration.
7. **Gates green:** helm lint + kubeconform + kube-linter + conftest/OPA + helm-unittest all pass in CI; **G-SEC** K8s-posture evidence note produced; G-OBS/G-MNT continuous green.
8. **README honest:** `deploy/kubernetes/netops/README.md` documents the chart as GA **and** states plainly that P1 is single-replica / **not** highly-available (HA is P2) (ADR-0029 Consequences).
9. Each of T1–T6 landed as **one atomic commit**, each with spec+quality review (strong) resolved and verifier-confirmed.

---

## 8. Risks & carry-forward

- **W3 ordering dependency** — if ADR-0031's deviation selector isn't final, T5's allow-list and conftest cardinality test block. Mitigation: T5 is last of the YAML tasks; T1–T4 proceed independently.
- **readOnlyRootFS missed scratch dir** surfaces only at runtime (third-party image writing outside enumerated `emptyDir`). Mitigation: per-image write-path tests in T6 (ADR-0029 Consequences/negative).
- **Install friction** — hardened defaults require cert-manager + ingress controller + Kyverno present; air-gapped installs mirror these. Documented as chart prerequisites with warned opt-outs for org-wide equivalents.
- **P2 policy churn** — the api→PG-direct edge becomes api→PgBouncer→PG, and single-replica becomes HA, in P2. Known scheduled edits, flagged in README, not silent drift.
- **Live-cluster apply deferred-accepted** (same posture as W1/W2 lab-defer): chart is render/lint/conftest-verified in CI; a real `helm install` against a live cluster runs from P2 when cluster access exists.
