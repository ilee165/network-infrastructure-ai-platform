#!/usr/bin/env bash
# HA topology readiness gate for the ephemeral kind HA cluster (P3 W4-T1,
# ADR-0047 / ADR-0048 §3; ADR-0042 CNPG, ADR-0044 Sentinel, ADR-0043 KEDA).
#
# Called by kind-harness.sh (HA=1) AFTER the reduced-scale HA overlay is applied.
# Gates the run on the HA workloads actually reaching a HEALTHY, HA state — a
# HALF-UP cluster (primary up, replicas Pending; Sentinels not yet monitoring;
# the CNPG Cluster not yet reporting a primary) must NOT read "ready" (L5 —
# the single most important reliability rule for a gate-hosting topology:
# ADR-0048 §3 requires this bring-up to be reliable enough that a red aggregator
# means a real regression, not a "still coming up" race).
#
# L5: `set -o pipefail` + `test -s` on every piped kubectl read, so a masked
# empty read (e.g. a `get -o jsonpath` that returns nothing because the resource
# does not exist yet) cannot be mistaken for the expected value.
# L3: no `$(VAR)` in an exec argv — this script drives kubectl directly.
#
# Idempotent + retried: each readiness assertion polls with a bounded timeout;
# a persistent not-ready is a HARD failure (exit non-zero), never a silent pass.

set -euo pipefail

CHART_NS="${CHART_NS:-netops}"
CNPG_CLUSTER_READY_TIMEOUT="${CNPG_CLUSTER_READY_TIMEOUT:-300s}"
WORKLOAD_READY_TIMEOUT="${WORKLOAD_READY_TIMEOUT:-240s}"
# How many CNPG instances the reduced-scale overlay declares (1 primary + 2
# replicas). Surfaced so the readiness count is asserted, not assumed.
CNPG_EXPECTED_INSTANCES="${CNPG_EXPECTED_INSTANCES:-3}"

log() { echo "== $* =="; }
group() { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }

# poll_jsonpath <resource> <jsonpath> <expected> <human-name> <timeout-seconds>
#   Poll a resource's jsonpath field until it EQUALS <expected>, or HARD-FAIL on
#   timeout. L5: the read is captured with pipefail on; an empty/absent value is
#   NOT the expected value, so a missing resource never reads as ready.
poll_jsonpath() {
  local resource="$1" path="$2" want="$3" name="$4" timeout="${5:-180}"
  local deadline got
  deadline=$(( $(date +%s) + timeout ))
  while :; do
    # `|| true` so a not-yet-existing resource (kubectl get exits non-zero) does
    # not abort under `set -e`; the emptiness is then compared against `want`.
    got="$(kubectl -n "${CHART_NS}" get ${resource} -o "jsonpath=${path}" 2>/dev/null || true)"
    if [ "${got}" = "${want}" ]; then
      echo "${name}: ${path} == ${want} (ready)"
      return 0
    fi
    if [ "$(date +%s)" -ge "${deadline}" ]; then
      echo "::error::${name} NOT ready within ${timeout}s — ${path} was '${got}', wanted '${want}'." \
           "A half-up HA topology must not read ready (L5 / ADR-0048 §3)." >&2
      kubectl -n "${CHART_NS}" get "${resource%% *}" -o wide || true
      return 1
    fi
    sleep 5
  done
}

# --- 1. CloudNativePG Cluster: primary elected + all instances ready ----------
group "CNPG Cluster readiness (1 primary + 2 replicas, ADR-0042 §1)"
# The CNPG Cluster status must report a healthy phase AND the full instance count
# ready — a primary-only cluster (replicas Pending) is NOT the HA quorum the
# failover drill needs. `.status.readyInstances` must equal the declared count.
poll_jsonpath "cluster" '{.items[0].status.readyInstances}' \
  "${CNPG_EXPECTED_INSTANCES}" "CNPG Cluster readyInstances" 300
# A current primary must be elected (empty currentPrimary = no writable primary).
cnpg_primary="$(kubectl -n "${CHART_NS}" get cluster -o jsonpath='{.items[0].status.currentPrimary}' 2>/dev/null || true)"
if [ -z "${cnpg_primary}" ]; then
  echo "::error::CNPG Cluster has NO currentPrimary — no writable primary; not ready (ADR-0042)." >&2
  kubectl -n "${CHART_NS}" get cluster -o wide || true
  endgroup
  exit 1
fi
echo "CNPG Cluster currentPrimary=${cnpg_primary}"
endgroup

# --- 2. Redis + Sentinel StatefulSets: all replicas ready ---------------------
group "Redis Sentinel readiness (3 Redis + 3 Sentinel, ADR-0044 §1)"
# Both StatefulSets must have every replica Ready — a Sentinel quorum that has not
# formed (Sentinels Pending) cannot perform failover, so the shard is not HA.
# `rollout status statefulset` blocks until .status.readyReplicas == .spec.replicas.
# Defense-in-depth: guard against an empty list so a namespace mishap or partial
# apply that dropped all StatefulSets does not silently pass this section (L5).
sts_list=$(kubectl -n "${CHART_NS}" get statefulset \
    -l app.kubernetes.io/name=netops -o name 2>/dev/null || true)
if [ -z "${sts_list}" ]; then
  echo "::error::no StatefulSets found in ${CHART_NS} — Redis/Sentinel did not render/apply." >&2
  endgroup
  exit 1
fi
for sts in ${sts_list}; do
  echo "waiting for ${sts} rollout"
  kubectl -n "${CHART_NS}" rollout status "${sts}" --timeout="${WORKLOAD_READY_TIMEOUT}"
done
endgroup

# --- 3. api + worker Deployments (+ KEDA per-queue workers) available ----------
group "api + worker Deployments availability (api HPA floor 2, KEDA per-queue)"
# Every Deployment in the namespace must reach Available — this covers the api
# (HPA floor 2), the base worker, the frontend, and the KEDA-owned per-queue
# worker Deployments. A per-queue worker stuck Pending means KEDA's scale target
# is not schedulable and a queue-burst drill would false-green.
# L5 / ADR-0048 §3: capture the list first; an empty list means no Deployments
# landed (partial apply, wrong namespace) — that MUST hard-fail, not silently
# skip the loop body and return 0 (false-green on a zero-Deployment cluster).
dep_list=$(kubectl -n "${CHART_NS}" get deployment -o name 2>/dev/null || true)
if [ -z "${dep_list}" ]; then
  echo "::error::no Deployments found in ${CHART_NS} — api/worker/frontend did not render/apply." >&2
  endgroup
  exit 1
fi
for dep in ${dep_list}; do
  echo "waiting for ${dep} rollout"
  kubectl -n "${CHART_NS}" rollout status "${dep}" --timeout="${WORKLOAD_READY_TIMEOUT}"
done
endgroup

# --- 4. KEDA ScaledObjects reconciled (Ready) ---------------------------------
group "KEDA ScaledObject reconciliation (per-queue isolation substrate, ADR-0043)"
# Each ScaledObject must report Ready=True — an unreconciled ScaledObject (bad
# trigger, unresolved TriggerAuthentication) means the queue is not actually
# autoscaled and the isolation the W4-T6 drill asserts would be vacuous.
so_names="$(kubectl -n "${CHART_NS}" get scaledobject -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)"
if [ -z "${so_names}" ]; then
  echo "::error::no KEDA ScaledObjects present in ${CHART_NS} — the KEDA substrate did not render/apply." >&2
  endgroup
  exit 1
fi
for so in ${so_names}; do
  poll_jsonpath "scaledobject/${so}" \
    '{.status.conditions[?(@.type=="Ready")].status}' \
    "True" "ScaledObject/${so} Ready" 180
done
endgroup

log "HA topology READY — CNPG primary + ${CNPG_EXPECTED_INSTANCES} instances, Redis+Sentinel, api/worker+KEDA ScaledObjects reconciled"
