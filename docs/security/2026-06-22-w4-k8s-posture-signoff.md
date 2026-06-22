# W4 K8s-Posture Sign-Off — netops GA Helm Chart (G-SEC evidence)

**Date:** 2026-06-22
**Milestone:** P1 W4 (Helm / K8s GA chart + hardening round 1)
**Authority:** CLAUDE.md "Development Standards" step 5 (security review) +
"Production Readiness"; `docs/roadmap/P1-W4-PLAN.md` §5 (gates) / §7 (exit
criteria); ADR-0029 (K8s/Helm GA + hardening R1), ADR-0031 (packet sandbox),
ADR-0012 §2 (same-origin proxy), ADR-0015 §4 (probe paths), ADR-0028 (OIDC
secret), ADR-0032 (KMS), PRODUCTION.md §9 / §3.1 / §11 (gate mapping).
**Gate:** **G-SEC** (K8s-posture — primary), with G-OBS (probes wired) and
G-MNT (chart lint/maintainability) continuous-green.
**Purpose:** the G-SEC K8s-posture evidence artifact for the GA chart. It lists
the rendered hardening controls and the green gate output proving exit criteria
§7.1–§7.7. It is produced by W4-T6, which also folded in the two W3 CI
deferred-minors (conftest flag, Trivy config gating) and strengthened the Rego.

Legend: **PASS** = control rendered by the chart's hardened **default** values,
asserted on the rendered manifests by `conftest`/`kube-linter`, and gate-verified.

---

## Gate output (rendered GA chart, single namespace `netops`, K8s 1.29.0)

```
helm lint deploy/kubernetes/netops
  => 1 chart(s) linted, 0 chart(s) failed

helm template netops deploy/kubernetes/netops --namespace netops \
  --kube-version 1.29.0 | tr -d '\r'
  => 39 objects rendered:
       1 Certificate   1 ClusterPolicy   2 ConfigMap   1 DaemonSet
       5 Deployment    1 Ingress         2 Namespace    8 NetworkPolicy
       1 Secret        5 Service         9 ServiceAccount  3 StatefulSet

kubeconform -strict -summary -kubernetes-version 1.29.0 \
  -ignore-missing-schemas -skip ClusterPolicy
  => 39 resources found - Valid: 37, Invalid: 0, Errors: 0, Skipped: 2
       (Skipped: the Kyverno ClusterPolicy CRD has no built-in schema; the
        ValidatingAdmissionPolicy fallback is not rendered with engine=kyverno)

kube-linter lint --config deploy/kubernetes/.kube-linter.yaml
  => No lint errors found!

conftest test --policy deploy/kubernetes/policy/rego --all-namespaces
  => 2691 tests, 2691 passed, 0 warnings, 0 failures, 0 exceptions
       (69 deny rules in netops.hardening, evaluated per rendered document)

trivy config --scan-ref deploy --severity CRITICAL,HIGH \
  --ignore-unfixed --exit-code 1
  => GATING on fixable HIGH/CRIT IaC misconfig (runs in CI; trivy is CI-only)
```

All five locally-runnable gates pass on the rendered chart. The CI `infra` job
(`.github/workflows/ci.yml`) runs the same five plus the gating Trivy config scan.

---

## §7.1 — Secure-by-default verified (PASS)

Namespace-wide `restricted` PSS (`enforce/audit/warn: restricted` on the install
`Namespace`); the capture namespace is the single documented relaxed exception
(ADR-0031 §5). Every per-container control is the hardened **default**, rendered
from `netops.hardenedSecurityContext` / `netops.podSecurityContext` so it cannot
drift per-service:

| Control | Default | Evidence (rendered) |
|---|---|---|
| `runAsNonRoot: true`, `runAsUser/Group: 10001` | on | every container + pod securityContext |
| `allowPrivilegeEscalation: false` | on | every platform container |
| `capabilities.drop: ["ALL"]` (no `add`) | on | every platform container |
| `readOnlyRootFilesystem: true` | on | every platform container (writable scratch = enumerated `emptyDir`) |
| `seccompProfile.type: RuntimeDefault` | on | every platform container + pod (Localhost only on the packet sandbox) |
| resource `requests` + `limits` | on | every platform container |

These are asserted **generically** on EVERY platform workload (api/worker/frontend
+ postgres/neo4j/redis/ollama, across Deployment **and** StatefulSet) by the new
`is_platform_workload` rule set in `deploy/kubernetes/policy/rego/hardening.rego`
(W4-T6) — not just the packet-* workloads the W3 rules named. Disabling any
control is a `values.yaml` opt-out that emits a Helm `NOTES` warning
(`templates/NOTES.txt` `_warnings` list). No control is opt-in.

Mutation-tested: flipping `readOnlyRootFilesystem` to `false` and gutting the
`disallow-latest-tag` admission pattern both make `conftest` FAIL — the rules are
non-vacuous.

## §7.2 — NetworkPolicies are the firewall spec (PASS)

`*-default-deny-all` selects all pods (`podSelector: {}`) and declares both
Ingress + Egress with NO allow rules (the floor stays empty). Every additive
allow maps edge-for-edge to an ADR-0029 §2 / PRODUCTION.md §3.1 arrow; egress
ports are confined to the known set `{5432, 7687, 6379, 11434, 443, 53}`; no
egress rule omits `to` (no blanket egress). External-LLM egress is opt-in,
default-off (the `external-llm-egress` policy must NOT render by default — a deny
rule guards its absence). Asserted by the §2 firewall rules in the Rego.

## §7.3 — Ingress TLS-only (PASS)

One HTTPS-only `Ingress` (8 NetworkPolicies include the `ingress → frontend` edge
as the SOLE front door; no direct `ingress → api` door — ADR-0012 §2). cert-manager
`Certificate` references `ingress.tls.issuerRef`; the TLS Secret is cert-manager
-managed, never templated (no key in values or release history). ssl-redirect +
HSTS are default annotations. All 5 Services are `ClusterIP`; a `type` override is
a warned opt-out (NOTES). kube-linter + kubeconform pass on the rendered Ingress.

## §7.4 — Admission allow-list singular (PASS)

The Kyverno `ClusterPolicy netops-hardening-baseline` ships `disallow-latest-tag`,
`require-image-tag-or-digest`, `verify-image-signatures` (cosign, data-gated to
W6), and the PSS-deviation allow-list `restrict-net-raw-to-packet-sandbox` +
`restrict-custom-seccomp-to-packet-sandbox`. W4-T6 added **rule-body** assertions
on top of the W3 name-only (`has_rule`) checks: `disallow-latest-tag` must carry a
`validate.pattern` that bans `:latest`, and the `restrict-net-raw` exclude selector
must match EXACTLY the one-key `netops.io/net-raw` deviation label (no broader/empty
selector). Cardinality = 1: `net_raw_allowed_workload := "packet-capture"` — any
other Deployment carrying the deviation label fails; every W4 platform Deployment
must stay SUBJECT to the rule. A VAP fallback (`engine=vap`) mirrors the intent.

## §7.5 — Secrets by reference only (PASS)

With `secrets.existingSecret` set, the chart renders **zero** Secret objects
(verified: `helm template --set secrets.existingSecret=... | grep -c 'kind: Secret'`
= 0). The only Secret that may render is the marked dev-convenience one
(`netops.io/dev-secret: "true"`), holding render-time `randAlphaNum` placeholders —
never an authored literal. W4-T6 added two Rego guards: (1) any chart-shipped
Secret OTHER than the marked dev one is denied; (2) the dev Secret's
credential-looking keys must hold generated placeholders, not inlined literals
(mutation-tested: inserting `P@ssw0rd:literal` makes conftest FAIL). Device
credentials never become K8s objects (D11, structural). The master key is a KMS
reference/handle, never the KEK (ADR-0032). No credential/master-key/OIDC-secret
literal appears in any template, value, log, or this note.

## §7.6 — Probes bound (PASS, G-OBS)

`api` liveness `/api/v1/health/live` + readiness `/api/v1/health/ready` :8000 +
startupProbe (failureThreshold 30 for slow boot / Alembic); `worker` celery-ping
exec + broker reachability; `frontend` `/healthz` :8080; data stores native. Paths
are the ADR-0015 §4 canonical ones. kube-linter's readiness/liveness checks pass.

## §7.7 — Gates green + this evidence note (PASS)

helm lint + kubeconform + kube-linter + conftest (`--all-namespaces`) all pass on
the rendered chart (output above); Trivy config gates in CI on fixable HIGH/CRIT
IaC misconfig. G-OBS (probes) and G-MNT (lint clean) are continuous-green.

---

## W3 CI deferred-minors folded in (W4-T6)

1. **conftest flag contradiction fixed.** The `infra` job ran
   `conftest ... --namespace netops.hardening --all-namespaces` (a single explicit
   namespace AND "all" — contradictory). Now `--all-namespaces` only, so every
   Rego package runs unambiguously. The Rego lives in one package
   (`netops.hardening`); both invocations resolved identically, so the fix is
   behaviour-preserving and future-package-safe.
2. **Trivy config scan now gates.** Was `exit-code: "0"` (non-gating). Now
   `exit-code: "1"` with `ignore-unfixed: true` — it gates on fixable HIGH/CRIT
   IaC misconfig on the chart + compose sources, mirroring the image-scan posture,
   scoped to `scan-type: config` so it does NOT duplicate conftest's policy
   semantics (conftest = ADR-0029/0031 control assertions on rendered manifests;
   Trivy = generic IaC best-practice misconfig on sources).
3. **Compose seccomp relative-path hardened.** `deploy/docker/docker-compose.yml`
   `packet-analysis` used `seccomp=./seccomp/...` — a path Docker resolves against
   the **client CWD**, which broke under the documented run-from-repo-root
   convention. Now
   `seccomp=${NETOPS_SECCOMP_PROFILE:-./deploy/docker/seccomp/packet-analysis-seccomp.json}`:
   the default resolves correctly from the repo root, and an absolute-path override
   is documented for other CWDs / air-gapped mirrors (compose README). Kept in
   byte-for-byte lockstep with the chart's Localhost profile (ADR-0031 §3).

## Single-replica / non-HA (honest)

P1 GA is **single-replica**: one replica per workload, no HPA/KEDA/operator/PDB.
A node loss takes a service down until reschedule — **no in-cluster HA**. HA is
**P2** (ADR-0029 §0/§1). The `services.<svc>.replicas` keys are the P2 seam;
raising one alone gives no autoscaling/disruption budget and emits a NOTES warning.
Stated plainly in `deploy/kubernetes/netops/README.md` and
`deploy/kubernetes/README.md`.

## Deferred / accepted

- **Live-cluster apply deferred-accepted** (same posture as W1/W2/W3 lab-defer):
  the chart is render/lint/kubeconform/kube-linter/conftest-verified in CI; a real
  `helm install` against a live cluster runs from P2 when cluster access exists
  (P1-W4-PLAN §8).
- **cosign enforcement + SBOM (syft) producing pipeline → W6.** This chart is the
  admission *enforcement* side; `verify-image-signatures` renders Audit-only until
  W6 wires a real verifier key (`admission.signedImages.enabled`, default off).
- **api→PgBouncer→PG NetworkPolicy rewrite + HA → P2** (known scheduled edits,
  flagged in the chart README, not silent drift).
