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
#        if a harness default-deny does not block a known egress. As of P3 W4-T2
#        (ADR-0048) the P2 `kind-harness` CI job is BLOCKING (in `all-gates` needs,
#        no continue-on-error) for the two G-SEC live assertions — the mTLS handshake
#        refusal + collector default-deny egress — after each was PROVEN TO BITE on a
#        planted regression and reverted; kind cannot run on the Windows authoring
#        host, so that bite runs on the CI runner. The `kind-harness-ha` HA job stays
#        non-blocking (see ci.yml `kind-harness` job + docs/runbooks/kind-harness.md).
#   L5 — `set -o pipefail` + `test -s` on every render/apply/assert pipe so a
#        masked exit code can never read green.
#   L3 — any value an in-cluster exec needs is passed as a positional arg to
#        `sh -c` ("$1"), never $(VAR)-interpolated into an exec argv.
#
# Usage:
#   ci/kind/kind-harness.sh            # full run (bring-up → assert → teardown)
#   HA=1 ci/kind/kind-harness.sh       # ADD the reduced-scale HA topology (P3 W4-T1):
#                                      #   install the CNPG operator + KEDA, then apply
#                                      #   the values-kind-ha.yaml overlay (CNPG 1+2,
#                                      #   Redis Sentinel 3+3, KEDA per-queue workers,
#                                      #   api HPA floor 2) and GATE on HA readiness.
#                                      #   The P2 CNI self-test + mTLS/collector
#                                      #   assertions run UNCHANGED alongside.
#   KEEP_CLUSTER=1 ci/kind/kind-harness.sh   # skip teardown for local debugging
#
# Requires: kind, kubectl, helm on PATH (the CI job installs them; locally install
# kind + a Docker/Podman backend first — see the runbook).
#
# P3 W4-T1 (ADR-0047 / ADR-0048 §3): the HA path is an ADD-ON composed onto the
# EXISTING P2 harness — it reuses the SAME Calico bring-up + CNI self-test (does
# NOT duplicate them) and leaves the P2 mTLS + collector-egress assertions intact.
# When HA=1 it installs the CNPG operator + KEDA (ci/kind/ha/install-operators.sh,
# pinned versions), renders the chart WITH the reduced-scale HA overlay, and gates
# on HA readiness (ci/kind/ha/wait-ha-ready.sh) so a half-up cluster never reads
# ready (L5). L1: kind cannot run on the Windows authoring host — the HA live path
# is authored + statically validated here and runs LIVE only on the CI ubuntu
# runner; the `kind-harness-ha` CI job stays continue-on-error / non-blocking (its
# G-REL/G-SCA promotion is a deliberate W5/GA step). W4-T2 (ADR-0048) promoted the
# P2 `kind-harness` job — the G-SEC mTLS + collector-egress live assertions — to
# blocking; this HA add-on is NOT part of that promotion.

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

# --- P3 W4-T1 HA add-on (ADR-0047 / ADR-0048 §3) -----------------------------
# HA=1 turns on the reduced-scale HA topology: install the CNPG operator + KEDA,
# render the chart with the values-kind-ha.yaml overlay, gate on HA readiness.
# Default OFF so the P2 harness behaviour is byte-for-byte unchanged when HA is
# not requested. These are the SIBLING scripts the HA path composes (the P2 CNI
# self-test + assertions are untouched).
HA="${HA:-0}"
HA_INSTALL_OPERATORS="${HA_INSTALL_OPERATORS:-${HERE}/ha/install-operators.sh}"
HA_WAIT_READY="${HA_WAIT_READY:-${HERE}/ha/wait-ha-ready.sh}"
# The reduced-scale HA overlay (CNPG 1+2, Redis Sentinel 3+3, KEDA per-queue
# workers, api HPA floor 2). Layered ON TOP of the chart defaults via helm -f.
HA_VALUES="${HA_VALUES:-${CHART_DIR}/values-kind-ha.yaml}"

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
# NO `--wait` here: kind-config.yaml sets `disableDefaultCNI: true`, so the
# cluster comes up with NO CNI and the node stays NotReady (CoreDNS Pending)
# until Calico is applied in step 2. `--wait` would block on a readiness that
# CANNOT be reached pre-CNI and, under `set -e`, abort the harness BEFORE the
# CNI is ever installed (the canonical kind+Calico ordering trap). Readiness is
# gated AFTER Calico via `kubectl wait --for=condition=Ready nodes` (line below).
kind create cluster --name "${CLUSTER_NAME}" --config "${KIND_CONFIG}"

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

# --- 3a. HA add-on: install the CNPG operator + KEDA (P3 W4-T1) ----------------
# Only when HA=1. This runs AFTER the CNI self-test proved the CNI enforces (the
# HA operators + HA overlay do not weaken that guarantee), and BEFORE the chart
# render/apply so the CNPG Cluster / KEDA ScaledObject CRDs exist when applied.
# The installer is pinned + idempotent + retried + readiness-gated (L1/L5).
if [ "${HA}" = "1" ]; then
  log "HA=1 — installing HA operators (CloudNativePG + KEDA) before chart apply"
  bash "${HA_INSTALL_OPERATORS}"
fi

# --- 4. render + apply the chart manifests ------------------------------------
log "rendering netops chart"
RENDERED="$(mktemp)"
# W4-T4: render with api/worker↔postgres mTLS ON, via the DEV-FALLBACK cert path
# (certManager.enabled=false) — the bare harness installs no cert-manager, so the
# chart's `lookup` reuse-or-generate Secret material is what postgres/api/worker
# mount, and the mtls-postgres.sh assertion can prove the handshake + plaintext/
# wrong-CA refusal (ADR-0039 §6). Override MTLS_VALUES to test the cert-manager
# path on a harness that pre-installs cert-manager.
MTLS_VALUES=(
  --set mtls.postgres.enabled="${MTLS_ENABLED:-true}"
  --set mtls.postgres.certManager.enabled="${MTLS_CERT_MANAGER:-false}"
)
# P3 W4-T1: when HA=1, layer the reduced-scale HA overlay ON TOP of the chart
# defaults (CNPG 1+2, Redis Sentinel 3+3, KEDA per-queue workers, api HPA floor
# 2). Passed as a helm `-f` so it composes with (and is overridden by) the
# --set MTLS flags above — the mTLS path is preserved under HA. Empty when HA off,
# so the P2 render is byte-for-byte unchanged.
HA_FILE_ARGS=()
if [ "${HA}" = "1" ]; then
  HA_FILE_ARGS=(-f "${HA_VALUES}")
fi
# L5: pipefail so a helm-template failure is not masked by the `tr` pipe; CRLF is
# stripped (matches the `infra` job) and `test -s` guards an empty render.
set -o pipefail
helm template netops "${CHART_DIR}" \
  --namespace "${CHART_NS}" \
  --kube-version 1.29.0 \
  "${HA_FILE_ARGS[@]}" \
  "${MTLS_VALUES[@]}" \
  | tr -d '\r' > "${RENDERED}"
test -s "${RENDERED}"
log "applying chart manifests into namespace ${CHART_NS}"
kubectl create namespace "${CHART_NS}" --dry-run=client -o yaml | kubectl apply -f -
# server-side apply tolerates the CRD-order churn (cert-manager / Kyverno CRDs are
# out-of-scope for this scaffold; `--validate=false` is intentionally NOT set —
# we want schema validation. CRD-dependent objects are owned by W4-T4/T5, which
# install their prerequisites before applying).
#
# N6: do NOT blanket-catch ALL apply failures. The ONLY tolerable error is a
# MISSING OPTIONAL CRD (cert-manager / Kyverno) — kubectl reports those as
# `no matches for kind … in version …` / `unable to recognize … ensure CRDs are
# installed`. ANY OTHER apply failure (a broken Deployment / Secret /
# NetworkPolicy, a schema rejection, an admission denial) means the harness would
# run assertions against an INCOMPLETE chart = false-green; that is a HARD FAILURE.
#
# N6.1 (PR#76 round 2, #15): default FAIL-CLOSED. The prior else branch grepped
# FOR a fixed set of error patterns and only failed when it could POSITIVELY
# identify an "unexpected" line. If apply failed with text matching NONE of those
# patterns (a connection/timeout error, an admission webhook denial worded
# differently, a server-side parse error), `unexpected` was EMPTY and the harness
# FELL THROUGH to the warning + assertions = fail-open against an incomplete chart.
# We now invert the logic: a NON-ZERO apply is a HARD FAIL UNLESS *every*
# non-trivial line of the apply log is provably either a successful-apply line or
# the known optional-CRD-missing class. We SUBTRACT the known-good lines from the
# WHOLE log; ANY residue (including lines no positive pattern would have caught)
# fails the run. There is no path from a failed apply to the assertions that does
# not first prove the entire log is accounted for.
apply_log="${APPLY_LOG:-$(mktemp)}"
if kubectl apply -n "${CHART_NS}" -f "${RENDERED}" 2>&1 | tee "${apply_log}"; then
  log "all chart objects applied cleanly"
else
  # Apply returned NON-ZERO. Start fail-closed: take EVERY non-blank log line and
  # subtract the lines we can ACCOUNT FOR — successful per-object apply outputs
  # (`<kind>/<name> created|configured|unchanged|serverside-applied`) and the
  # tolerated optional-CRD-missing error class. Whatever REMAINS is an
  # unaccounted-for failure, so the chart is incomplete -> HARD FAIL.
  #   - `grep -E '\S'`            : drop blank lines.
  #   - first `grep -vE` (good)   : drop successful-apply object lines.
  #   - second `grep -vE` (crd)   : drop the known optional-CRD-missing error text.
  # `|| true` keeps the pipeline alive when a stage matches nothing (empty residue
  # is the GOOD case here); the residue emptiness is what we then gate on.
  residue="$(grep -E '\S' "${apply_log}" \
    | grep -vE '^(configmap|secret|service|serviceaccount|deployment|deployment\.apps|statefulset|statefulset\.apps|daemonset|daemonset\.apps|cronjob|cronjob\.batch|job|job\.batch|networkpolicy|networkpolicy\.networking\.k8s\.io|role|rolebinding|clusterrole|clusterrolebinding|ingress|ingress\.networking\.k8s\.io|persistentvolumeclaim|poddisruptionbudget|namespace|priorityclass|horizontalpodautoscaler)[^ ]* (created|configured|unchanged|serverside-applied)$' \
    | grep -vE 'no matches for kind|unable to recognize|ensure CRDs are installed|the server could not find the requested resource' \
    || true)"
  if [ -n "${residue}" ]; then
    echo "::error::chart apply FAILED and the apply log contains lines that are NEITHER a successful apply NOR the tolerated optional-CRD-missing class — the chart is incomplete; refusing to run assertions against it (fail-closed, N6/#15):" >&2
    printf '%s\n' "${residue}" >&2
    exit 1
  fi
  # Reaching here means apply was non-zero but EVERY non-blank line was either a
  # successful apply or a tolerated CRD-missing error — the only fall-through.
  echo "::warning::some chart objects require optional CRDs the scaffold does not" \
       "install (cert-manager / Kyverno) — W4-T4/T5 install their prerequisites." \
       "Only those CRD-missing errors were tolerated; the scaffold continues." >&2
fi

# --- 4a. HA add-on: gate on HA readiness (P3 W4-T1) ---------------------------
# Only when HA=1. A half-up HA topology (primary up but replicas Pending, the
# Sentinel quorum not formed, an unreconciled ScaledObject) must NOT read "ready"
# and must NOT let the assertions run against it (L5 / ADR-0048 §3 reliability
# prerequisite). This gate HARD-FAILS the run until every HA workload is healthy.
if [ "${HA}" = "1" ]; then
  log "HA=1 — gating on reduced-scale HA topology readiness (CNPG + Sentinel + KEDA)"
  CHART_NS="${CHART_NS}" bash "${HA_WAIT_READY}"
fi

# --- 5. run the assertion-runner (W4-T4 + W4-T5 checks) -----------------------
log "running assertion-runner (handshake + deny checks plug in here)"
ASSERT_LOG_DIR="${ASSERT_LOG_DIR:-$(mktemp -d)}"
export ASSERT_LOG_DIR CHART_NS SELFTEST_NS PROBE_HOST PROBE_PORT
bash "${ASSERT_RUNNER}"

log "harness complete — all assertions passed (teardown runs on exit)"
