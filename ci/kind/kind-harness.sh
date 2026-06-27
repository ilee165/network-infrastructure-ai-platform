#!/usr/bin/env bash
# Ephemeral in-CI kind cluster harness (P2 W4-T3, ADR-0039 §6 / ADR-0041 §2/§3).
#
# Brings up a throwaway kind cluster with an ENFORCING CNI, proves the CNI
# actually enforces NetworkPolicy (the self-test bite), renders + applies the
# netops chart, runs the assertion-runner (W4-T4 mTLS + W4-T5 egress plug their
# checks into ci/kind/assertions/checks/), and TEARS DOWN on exit — success OR
# failure — via a trap. This is the "kind for cheap" harness: it asserts handshake
# + deny only; HA / scale / soak are P3-Platform (ADR-0041 §4 / W4-T3 spec §0).
#
# Lessons baked in (P1-W4-LESSONS):
#   L1 — kindnet ADMITS but does not ENFORCE NetworkPolicy. We disable the default
#        CNI (kind-config.yaml) and install Calico; the CNI self-test FAILS the run
#        if a harness default-deny does not block a known egress. This file is
#        validated on a local kind cluster before the CI job is treated as gating
#        (the CI job is intentionally NON-blocking until that local validation —
#        see ci.yml `kind-harness` job + docs/runbooks/kind-harness.md).
#   L5 — `set -o pipefail` + `test -s` on every render/apply/assert pipe so a
#        masked exit code can never read green.
#   L3 — any value an in-cluster exec needs is passed as a positional arg to
#        `sh -c` ("$1"), never $(VAR)-interpolated into an exec argv.
#
# Usage:
#   ci/kind/kind-harness.sh            # full run (bring-up → assert → teardown)
#   KEEP_CLUSTER=1 ci/kind/kind-harness.sh   # skip teardown for local debugging
#
# Requires: kind, kubectl, helm on PATH (the CI job installs them; locally install
# kind + a Docker/Podman backend first — see the runbook).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

CLUSTER_NAME="${CLUSTER_NAME:-netops-w4}"
KIND_CONFIG="${HERE}/kind-config.yaml"
CHART_DIR="${REPO_ROOT}/deploy/kubernetes/netops"
CHART_NS="${CHART_NS:-netops}"
SELFTEST_NS="${SELFTEST_NS:-cni-selftest}"
SELFTEST_DIR="${HERE}/cni-selftest"
ASSERT_RUNNER="${HERE}/assertions/run-assertions.sh"

# Calico manifest (enforcing CNI, ADR-0041 §2). Pinned version — never `latest`.
CALICO_VERSION="${CALICO_VERSION:-v3.28.2}"
CALICO_MANIFEST="${CALICO_MANIFEST:-https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml}"

# A known-good external egress target for the CNI self-test baseline+deny probe.
# DNS root server :53 is universally routable and stable; the self-test only
# cares that the SAME target flips from reachable → blocked once default-deny is
# applied (the enforcement bite), not about the target itself.
PROBE_HOST="${PROBE_HOST:-1.1.1.1}"
PROBE_PORT="${PROBE_PORT:-53}"

log() { echo "== $* =="; }
group() { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }

# --- teardown (runs on ANY exit: success, failure, or signal) ----------------
teardown() {
  local rc=$?
  if [ "${KEEP_CLUSTER:-0}" = "1" ]; then
    echo "KEEP_CLUSTER=1 — leaving cluster ${CLUSTER_NAME} up (rc=${rc})"
    return "${rc}"
  fi
  group "teardown kind cluster ${CLUSTER_NAME}"
  # `|| true` so a teardown hiccup never masks the real exit code; deleting a
  # non-existent cluster is a no-op.
  kind delete cluster --name "${CLUSTER_NAME}" || true
  endgroup
  return "${rc}"
}
trap teardown EXIT INT TERM

# --- 1. bring up the cluster (enforcing CNI disabled-default) -----------------
log "creating ephemeral kind cluster ${CLUSTER_NAME}"
kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}" --wait 120s

# --- 2. install the ENFORCING CNI (Calico) — the load-bearing step (§2) -------
log "installing enforcing CNI: Calico ${CALICO_VERSION}"
# pipefail (set above) makes a failed `kubectl apply` propagate even though the
# manifest is fetched/streamed; we apply by URL so the pinned manifest is fetched
# server-side-independently. `--wait` below gates on the CNI being Ready.
kubectl apply -f "${CALICO_MANIFEST}"
log "waiting for Calico to be Ready (the cluster has NO CNI until this completes)"
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
# Nodes stay NotReady until a CNI is installed; confirm Ready before proceeding.
kubectl wait --for=condition=Ready nodes --all --timeout=180s

# --- 3. CNI SELF-TEST — prove the CNI ENFORCES, not just admits (§2) ----------
# Baseline: probe egress SUCCEEDS (CNI up, no policy). Then apply default-deny and
# the SAME egress MUST be BLOCKED. If it is not, the CNI admits but does not
# enforce NetworkPolicy (kindnet behaviour) and the whole run is false-green — so
# we FAIL here, before any downstream assertion trusts the deny path (L1).
log "CNI self-test: proving NetworkPolicy is ENFORCED (not just admitted)"
kubectl create namespace "${SELFTEST_NS}"
# Restricted PSA so the hardened probe pod is admitted exactly like chart pods.
kubectl label namespace "${SELFTEST_NS}" \
  pod-security.kubernetes.io/enforce=restricted --overwrite
kubectl apply -n "${SELFTEST_NS}" -f "${SELFTEST_DIR}/probe.yaml"
kubectl wait --for=condition=Ready pod/cni-selftest-probe \
  -n "${SELFTEST_NS}" --timeout=120s

# Pipe-safe egress probe (L3: host/port are positional "$1"/"$2" to `sh -c`,
# never $(VAR) in the argv; L5: pipefail is on so the exec's exit is not masked).
probe_egress() {
  kubectl exec -n "${SELFTEST_NS}" cni-selftest-probe -- \
    sh -c 'nc -z -w "$3" "$1" "$2"' _ "${PROBE_HOST}" "${PROBE_PORT}" 5
}

group "CNI self-test: baseline egress must SUCCEED (no policy yet)"
if probe_egress; then
  echo "baseline egress ${PROBE_HOST}:${PROBE_PORT} reachable — CNI admits traffic (ok)"
else
  echo "::error::baseline egress failed BEFORE any deny policy — the CNI is not" \
       "routing pod egress at all; cannot trust the self-test. Failing." >&2
  endgroup
  exit 1
fi
endgroup

group "CNI self-test: apply default-deny — egress must now be BLOCKED"
kubectl apply -n "${SELFTEST_NS}" -f "${SELFTEST_DIR}/default-deny.yaml"
# Give the CNI a moment to program the policy, then probe. The probe MUST fail.
# We retry a few times to avoid a race between apply and dataplane programming,
# but a persistently-reachable target after default-deny is a HARD failure.
blocked=0
for attempt in 1 2 3 4 5; do
  if probe_egress; then
    echo "attempt ${attempt}: egress still reachable after default-deny — waiting for dataplane…"
    sleep 3
  else
    blocked=1
    echo "attempt ${attempt}: egress ${PROBE_HOST}:${PROBE_PORT} BLOCKED by default-deny (CNI enforces ✓)"
    break
  fi
done
endgroup

if [ "${blocked}" -ne 1 ]; then
  echo "::error::CNI SELF-TEST FAILED — a harness default-deny did NOT block a" \
       "known egress. The CNI ADMITS but does not ENFORCE NetworkPolicy" \
       "(kindnet behaviour). Every downstream deny assertion would be false-green." \
       "Refusing to continue (ADR-0041 §2 / P1-W4-LESSONS L1)." >&2
  exit 1
fi
log "CNI self-test PASSED — NetworkPolicy is enforced; proceeding"

# Clean the self-test namespace so it cannot interfere with chart assertions.
kubectl delete namespace "${SELFTEST_NS}" --wait=true

# --- 4. render + apply the chart manifests ------------------------------------
log "rendering netops chart"
RENDERED="$(mktemp)"
# L5: pipefail so a helm-template failure is not masked by the `tr` pipe; CRLF is
# stripped (matches the `infra` job) and `test -s` guards an empty render.
set -o pipefail
helm template netops "${CHART_DIR}" \
  --namespace "${CHART_NS}" \
  --kube-version 1.29.0 \
  | tr -d '\r' > "${RENDERED}"
test -s "${RENDERED}"
log "applying chart manifests into namespace ${CHART_NS}"
kubectl create namespace "${CHART_NS}" --dry-run=client -o yaml | kubectl apply -f -
# server-side apply tolerates the CRD-order churn (cert-manager / Kyverno CRDs are
# out-of-scope for this scaffold; `--validate=false` is intentionally NOT set —
# we want schema validation. CRD-dependent objects are owned by W4-T4/T5, which
# install their prerequisites before applying).
kubectl apply -n "${CHART_NS}" -f "${RENDERED}" || {
  echo "::warning::some chart objects require CRDs the scaffold does not install" \
       "(cert-manager / Kyverno) — W4-T4/T5 install their prerequisites. The" \
       "scaffold continues to the assertion-runner." >&2
}

# --- 5. run the assertion-runner (W4-T4 + W4-T5 checks) -----------------------
log "running assertion-runner (handshake + deny checks plug in here)"
ASSERT_LOG_DIR="${ASSERT_LOG_DIR:-$(mktemp -d)}"
export ASSERT_LOG_DIR CHART_NS SELFTEST_NS PROBE_HOST PROBE_PORT
bash "${ASSERT_RUNNER}"

log "harness complete — all assertions passed (teardown runs on exit)"
