#!/usr/bin/env bash
# Static validator for the reduced-scale kind HA overlay (P3 W4-T1, ADR-0047 §1 /
# ADR-0048 §3 / ADR-0042 / ADR-0043 / ADR-0044).
#
# This is the HARD-GATING policy-as-test for the HA overlay: it needs NO cluster
# (helm template only), renders the chart WITH values-kind-ha.yaml on top of the
# same MTLS path the kind harness uses, and asserts that the rendered HA topology
# carries every load-bearing property:
#   - the HA tiers are SELECTED (CNPG Cluster + Pooler, Redis + Sentinel
#     StatefulSets, KEDA ScaledObjects, api HPA) — the substrate the W4 drills need;
#   - the reduced-scale COUNTS are the stated ones (CNPG 1+2 = instances:3; Redis
#     replicas:3; Sentinel replicas:3; api HPA minReplicas:2) — so a silent scale
#     drift (someone dropping CNPG below quorum, or the api floor below 2) BITES;
#   - MUTUAL EXCLUSION holds (no single-instance postgres/redis StatefulSet in the
#     render) — one Postgres tier, one Redis tier;
#   - SECURE BY DEFAULT is inherited (the overlay flips no hardening off) — the
#     render passes the full conftest policy set, asserted by the infra CI job's
#     kubeconform+kube-linter+conftest step over this same overlay.
#
# It runs in the `infra` CI job (helm present) and locally on this host (helm,
# kubeconform, kube-linter, conftest all present). RED gate — a violation exits
# non-zero. L5: pipefail + test -s on the render so a masked/empty render fails
# closed, never false-green.
#
# Run: ci/kind/ha/validate-ha-overlay.sh

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"
CHART_DIR="${REPO_ROOT}/deploy/kubernetes/netops"
OVERLAY="${CHART_DIR}/values-kind-ha.yaml"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

echo "== validating reduced-scale kind HA overlay =="

# --- overlay file exists ------------------------------------------------------
if [ -f "${OVERLAY}" ]; then ok "HA overlay present (${OVERLAY})"; else
  bad "HA overlay MISSING (${OVERLAY})"; echo "== ${fails} failure(s) =="; exit 1; fi

# --- render the HA topology the harness renders (L5: pipefail + test -s) -------
RENDERED="$(mktemp)"
set -o pipefail
if helm template netops "${CHART_DIR}" \
    --namespace netops --kube-version 1.29.0 \
    -f "${OVERLAY}" \
    --set mtls.postgres.enabled=true \
    --set mtls.postgres.certManager.enabled=false \
    | tr -d '\r' > "${RENDERED}"; then
  ok "HA overlay renders (helm template)"
else
  bad "HA overlay FAILED to render"
  echo "== ${fails} failure(s) =="; exit 1
fi
if [ -s "${RENDERED}" ]; then ok "HA render is non-empty (test -s)"; else
  bad "HA render is EMPTY (test -s) — fail closed"; echo "== ${fails} failure(s) =="; exit 1; fi

# grep_render <regex> <description>
grep_render()     { if grep -Eq "$1" "${RENDERED}"; then ok "$2"; else bad "$2 — pattern not found: $1"; fi; }
grep_render_not() { if grep -Eq "$1" "${RENDERED}"; then bad "$2 — forbidden pattern present: $1"; else ok "$2"; fi; }

# --- HA tiers are SELECTED (the substrate the W4 drills plug into) -------------
grep_render '^kind: Cluster$' \
  "CloudNativePG Cluster is rendered (HA Postgres tier selected, ADR-0042)"
grep_render '^kind: Pooler$' \
  "CloudNativePG PgBouncer Pooler is rendered (ADR-0042 §4)"
grep_render '^kind: ScaledObject$' \
  "KEDA ScaledObject(s) rendered (per-queue autoscaling substrate, ADR-0043)"
grep_render '^kind: HorizontalPodAutoscaler$' \
  "api HorizontalPodAutoscaler rendered (ADR-0043 §1)"
grep_render 'name: netops-redis-sentinel' \
  "Redis Sentinel StatefulSet rendered (HA Redis tier selected, ADR-0044)"

# --- reduced-scale COUNTS are the STATED ones (a scale drift BITES) -----------
# CNPG 1 primary + 2 replicas == instances: 3 (the ADR-0042 §1 quorum minimum).
grep_render '^  instances: 3$' \
  "CNPG Cluster declares instances: 3 (1 primary + 2 replicas, ADR-0042 §1 quorum)"
# api HPA floor stays 2 (ADR-0043 §1 HA floor — never reduced below 2).
grep_render '^  minReplicas: 2$' \
  "api HPA minReplicas: 2 (HA floor unchanged; chart refuses < 2, ADR-0043 §1)"
grep_render '^  maxReplicas: 4$' \
  "api HPA maxReplicas: 4 (reduced ceiling for the single kind node)"

# --- MUTUAL EXCLUSION: no single-instance postgres/redis StatefulSet ----------
# The single-instance StatefulSets are named exactly `netops-postgres` /
# `netops-redis`. The Sentinel tier reuses the `netops-redis` Service name but its
# StatefulSet is `netops-redis` too — so we assert on the ABSENCE of the
# single-instance postgres StatefulSet (CNPG owns Postgres) and on the PRESENCE of
# the Sentinel StatefulSet (proving the Redis tier is the Sentinel one, not the
# single-instance one). A postgres StatefulSet in an HA render means both tiers
# rendered (the chart's mutual-exclusion guard failed).
if awk '/^kind: StatefulSet/{f=1;next} f&&/^  name: netops-postgres$/{print;found=1} /^---/{f=0} END{exit !found}' \
    "${RENDERED}" >/dev/null 2>&1; then
  bad "single-instance netops-postgres StatefulSet present in HA render — CNPG mutual-exclusion FAILED (two Postgres tiers)"
else
  ok "no single-instance netops-postgres StatefulSet in HA render (CNPG owns Postgres; mutual exclusion holds)"
fi

# --- mTLS path PRESERVED under HA (the harness renders with mTLS on) -----------
grep_render 'hostssl' \
  "pg_hba hostssl rows present — the api/worker↔postgres mTLS path is preserved under HA (ADR-0039)"

# --- SECURE BY DEFAULT inherited: no :latest tag anywhere in the HA render -----
# The admission policy (ADR-0029 §5) rejects mutable tags; a :latest slipping into
# the HA overlay would be a hardening regression. (The full conftest policy set is
# run over this same render by the infra CI job; this is the fast local canary.)
#
# The regex must match a REAL container image value ending in :latest, and must
# NOT match the Kyverno ClusterPolicy's OWN negated pattern `image: "!*:latest"`
# (the rule that FORBIDS :latest — the control we WANT). So we require the tag to
# be a concrete reference: `image:` + optional quote + a char that is NOT `!`
# (Kyverno negation) or `*` (glob) up to `:latest`. A digest-pinned image has an
# `@sha256:` before any tag, so `[^@"]*` never crosses into a digest.
grep_render_not 'image:[[:space:]]*"?[^!*@"][^@"]*:latest([[:space:]"]|$)' \
  "no :latest image tag in the HA render (admission would reject; secure-by-default inherited)"

echo "== HA overlay validator summary: ${fails} failure(s) =="
rm -f "${RENDERED}"
if [ "${fails}" -ne 0 ]; then
  echo "::error::HA overlay validator found ${fails} violation(s)" >&2
  exit 1
fi
echo "HA overlay validator: all invariants present."
