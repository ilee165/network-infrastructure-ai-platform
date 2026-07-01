#!/usr/bin/env bash
# HA operator installer for the ephemeral kind HA topology (P3 W4-T1, ADR-0047 /
# ADR-0048 §3; ADR-0042 CNPG, ADR-0043 KEDA).
#
# Installs the two HA OPERATORS the reduced-scale HA overlay needs on kind:
#   1. CloudNativePG operator (CNPG) — so a `Cluster` (1 primary + 2 replicas)
#      + `Pooler` can run on kind (ADR-0042 §1).
#   2. KEDA — so per-queue worker `ScaledObject`s + `TriggerAuthentication`s
#      resolve (ADR-0043 §2/§3/§4).
#
# The ENFORCING CNI (Calico) is NOT installed here — it is already brought up +
# self-tested by kind-harness.sh (ADR-0041 §2). This script is CALLED by the
# harness's HA path AFTER the CNI self-test passes; it does not duplicate the CNI
# bring-up (W4-T1 spec: reuse the existing Calico step, do not duplicate).
#
# Lessons baked in (P1-W4-LESSONS):
#   L1 — kind CANNOT run on the Windows authoring host (no Docker/Linux kind).
#        This installer is authored + statically validated (ci/kind/selftest/
#        validate-harness.sh) but its LIVE run is CI-only until W4-T2 promotes the
#        HA job. The static/render layers gate hard; the live bring-up is signal
#        (continue-on-error) for now.
#   L5 — `set -o pipefail` + `test -s` on every apply/wait/render pipe: a masked
#        exit code (a failed apply streamed through a pipe, an empty manifest) can
#        never read green. A half-installed operator must NOT report "ready".
#   L3 — no unsubstituted `$(VAR)` in any exec argv (none here — this installer
#        drives kubectl/helm directly, no in-pod exec).
#
# RELIABILITY (ADR-0048 §3 Prerequisite A — the load-bearing requirement): the
# install is DETERMINISTIC (pinned versions, never `latest`), IDEMPOTENT (apply is
# re-appliable; `--server-side --force-conflicts` tolerates a re-run), and RETRIED
# where the network is flaky (the manifest fetch + apply). Readiness is GATED with
# `kubectl rollout status` / `kubectl wait` so the harness never proceeds to a
# `Cluster`/`ScaledObject` apply against a controller that is not yet serving its
# webhooks/CRDs (the canonical "CRD not established" race).
#
# Usage: called by kind-harness.sh (HA=1). Run standalone against a kind cluster
# for local debugging: ci/kind/ha/install-operators.sh
#
# Requires: kubectl on PATH + a reachable cluster (KUBECONFIG / current-context).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- pinned operator versions (NEVER `latest` — matches the Calico pin) --------
# CloudNativePG operator. The release ships a single applyable manifest
# `cnpg-<version>.yaml`. Pinned; override with CNPG_VERSION for a newer pin.
CNPG_VERSION="${CNPG_VERSION:-1.24.1}"
CNPG_MANIFEST="${CNPG_MANIFEST:-https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-${CNPG_VERSION%.*}/releases/cnpg-${CNPG_VERSION}.yaml}"
CNPG_NAMESPACE="${CNPG_NAMESPACE:-cnpg-system}"

# KEDA. The release ships a single applyable manifest `keda-<version>.yaml`.
# Pinned; override with KEDA_VERSION for a newer pin.
KEDA_VERSION="${KEDA_VERSION:-2.16.1}"
KEDA_MANIFEST="${KEDA_MANIFEST:-https://github.com/kedacore/keda/releases/download/v${KEDA_VERSION}/keda-${KEDA_VERSION}.yaml}"
KEDA_NAMESPACE="${KEDA_NAMESPACE:-keda}"

# Readiness timeouts (bounded so a hung install fails the run rather than hanging
# CI to the job timeout).
OPERATOR_ROLLOUT_TIMEOUT="${OPERATOR_ROLLOUT_TIMEOUT:-240s}"
CRD_ESTABLISH_TIMEOUT="${CRD_ESTABLISH_TIMEOUT:-120s}"

log() { echo "== $* =="; }
group() { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }

# apply_manifest_retry <url> <human-name>
#   Idempotent, retried server-side apply of a pinned operator manifest. L5:
#   pipefail is set so a failed fetch/apply propagates; `test -s` guards an EMPTY
#   fetched manifest (a truncated download or a 404 HTML body) so a half/empty
#   manifest can never read as "applied". Retries the whole fetch+apply on a
#   transient network failure.
apply_manifest_retry() {
  local url="$1" name="$2"
  local manifest attempt=0 max=4
  manifest="$(mktemp)"
  group "install ${name} (pinned manifest)"
  while :; do
    attempt=$((attempt + 1))
    echo "fetch + apply ${name} (attempt ${attempt}/${max}): ${url}"
    # L5: pipefail + test -s. `kubectl create -f <url>` would not be idempotent on
    # a re-run; we FETCH then server-side apply so a re-run is a no-op/patch, not a
    # "already exists" error. curl -f fails on an HTTP error (a 404 will NOT be
    # written as a valid-looking body that test -s would then accept as content).
    if curl -fsSL "${url}" -o "${manifest}" && test -s "${manifest}"; then
      # server-side apply is idempotent + tolerates the CRD-owned-field churn a
      # re-apply of a large operator manifest produces (--force-conflicts).
      if kubectl apply --server-side --force-conflicts -f "${manifest}"; then
        echo "${name} manifest applied"
        endgroup
        rm -f "${manifest}"
        return 0
      fi
    fi
    if [ "${attempt}" -ge "${max}" ]; then
      echo "::error::${name} install FAILED after ${max} attempts (fetch or apply)" >&2
      endgroup
      rm -f "${manifest}"
      return 1
    fi
    echo "attempt ${attempt} failed; backing off before retry"
    sleep $((attempt * 5))
  done
}

# wait_crd_established <crd-name>...
#   Gate on each CRD reaching Established=True before any CR of that kind is
#   applied (the canonical "no matches for kind" race right after an operator
#   manifest apply). Retried implicitly by kubectl wait's own timeout; a missing
#   CRD after apply is a HARD failure.
wait_crd_established() {
  local crd
  for crd in "$@"; do
    echo "waiting for CRD ${crd} to be Established"
    # `--for=condition=Established` blocks until the api-server registers the CRD
    # schema; without this a following `kubectl apply` of a CR races the CRD.
    kubectl wait --for=condition=Established "crd/${crd}" \
      --timeout="${CRD_ESTABLISH_TIMEOUT}"
  done
}

# --- 1. CloudNativePG operator ------------------------------------------------
log "installing CloudNativePG operator v${CNPG_VERSION}"
apply_manifest_retry "${CNPG_MANIFEST}" "CloudNativePG operator v${CNPG_VERSION}"
wait_crd_established clusters.postgresql.cnpg.io poolers.postgresql.cnpg.io
group "wait for CloudNativePG controller to be Ready"
# The operator Deployment must be Available before it serves its admission webhook
# — a `Cluster` applied before the webhook is up is rejected with a webhook
# connection error. rollout status gates on that.
kubectl -n "${CNPG_NAMESPACE}" rollout status deployment/cnpg-controller-manager \
  --timeout="${OPERATOR_ROLLOUT_TIMEOUT}"
endgroup
log "CloudNativePG operator Ready (Cluster/Pooler CRDs Established)"

# --- 2. KEDA ------------------------------------------------------------------
log "installing KEDA v${KEDA_VERSION}"
apply_manifest_retry "${KEDA_MANIFEST}" "KEDA v${KEDA_VERSION}"
wait_crd_established scaledobjects.keda.sh triggerauthentications.keda.sh
group "wait for KEDA operator + metrics-apiserver to be Ready"
# The KEDA operator (reconciles ScaledObjects) AND the metrics apiserver
# (serves the external metrics the ScaledObject drives the HPA from) must both be
# Available before a ScaledObject is applied.
kubectl -n "${KEDA_NAMESPACE}" rollout status deployment/keda-operator \
  --timeout="${OPERATOR_ROLLOUT_TIMEOUT}"
kubectl -n "${KEDA_NAMESPACE}" rollout status deployment/keda-operator-metrics-apiserver \
  --timeout="${OPERATOR_ROLLOUT_TIMEOUT}"
endgroup
log "KEDA Ready (ScaledObject/TriggerAuthentication CRDs Established)"

log "HA operators installed + Ready — CNPG v${CNPG_VERSION}, KEDA v${KEDA_VERSION}"
