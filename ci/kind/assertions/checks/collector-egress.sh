#!/usr/bin/env bash
# W4-T5 collector/worker egress deny assertion (ADR-0041 §3) — plugged into the
# W4-T3 runner.
#
# THE BITE (deny proven, not nominal): with the chart's collector mgmt-egress
# NetworkPolicy applied (allow-collector-mgmt-egress) ON TOP OF the platform
# default-deny floor, against a probe pod that carries the WORKER labels (so both
# the default-deny floor AND the collector-egress policy select it), this check
# proves:
#   1. an ALLOWED egress — a NAMED in-cluster service the worker legitimately
#      reaches (Postgres :5432, re-permitted by the §2 allow-worker-egress policy)
#      — SUCCEEDS;
#   2. a DENIED egress — an ARBITRARY external destination (a public IP outside the
#      device mgmt subnet and outside the cluster) — is BLOCKED.
# Case 2 is the deterministic enforcement bite: it is valid ONLY because W4-T3
# installed an ENFORCING CNI and its CNI self-test passed (kindnet would admit the
# policy but not enforce it → false-green; ADR-0041 §2 / P1-W4-LESSONS L1). The
# harness runs this check ONLY after that self-test passes.
#
# It sources ../lib.sh and signals failure via assert_egress_allowed /
# assert_egress_blocked (the runner counts a non-zero assert_failures as a failed
# check). L3: every value the in-pod shell needs is a POSITIONAL arg to `sh -c`,
# never $(VAR) in an exec argv (lib.sh's _tcp_probe already does this). L5: pipefail
# is on (the runner sets it); this check tees nothing of its own but every probe
# runs under it.
#
# Like the W4-T4 mTLS check, this SKIPS LOUDLY (never silently false-green) if the
# collector mgmt-egress policy is absent — that means the chart was applied with
# networkPolicy.collectorEgress disabled, so there is no control to assert.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
. "${HERE}/../lib.sh"

NS="${CHART_NS:-netops}"
PROBE_POD="collector-egress-probe"
PROBE_MANIFEST="${HERE}/collector-egress-probe.yaml"

# The collector mgmt-egress NetworkPolicy the chart renders (W4-T5). Its presence
# is the precondition: absent => the chart was applied with collectorEgress off.
COLLECTOR_NETPOL="${COLLECTOR_NETPOL:-netops-allow-collector-mgmt-egress}"

# ALLOWED target: a NAMED in-cluster service the worker legitimately reaches. The
# §2 allow-worker-egress policy re-permits Postgres :5432; selecting the worker
# labels on the probe means that allow applies to it too. (Override PG_HOST/PG_PORT
# for a different named-service target.)
PG_HOST="${PG_HOST:-netops-postgres}"
PG_PORT="${PG_PORT:-5432}"

# DENIED target: an ARBITRARY external destination outside the device mgmt subnet
# and outside the cluster. The harness already uses 1.1.1.1:53 as a universally
# routable external probe target for the CNI self-test; reuse it so the deny bite
# targets the SAME class of destination the self-test proved is blockable.
DENY_HOST="${DENY_HOST:-${PROBE_HOST:-1.1.1.1}}"
DENY_PORT="${DENY_PORT:-${PROBE_PORT:-53}}"

echo "== W4-T5 collector/worker egress deny assertion (ns=${NS}) =="

# --- precondition: the collector mgmt-egress policy must be present, else SKIP ----
# (loudly — the runner also fails an EMPTY log, so we always emit output; a missing
# control read as a pass would be a false-green.)
if ! kubectl -n "${NS}" get networkpolicy "${COLLECTOR_NETPOL}" >/dev/null 2>&1; then
  echo "SKIP: NetworkPolicy ${COLLECTOR_NETPOL} absent — chart applied with"
  echo "      networkPolicy.collectorEgress OFF (or worker disabled). Enable it in"
  echo "      the harness apply to assert the allow/deny bite (W4-T5 live"
  echo "      validation is W5-promoted, like the W4-T4 mTLS check)."
  exit 0
fi

# --- bring up the worker-labelled probe pod -------------------------------------
cleanup() { kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=false || true; }
trap cleanup EXIT
kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=true || true
kubectl -n "${NS}" apply -f "${PROBE_MANIFEST}"
kubectl -n "${NS}" wait --for=condition=Ready "pod/${PROBE_POD}" --timeout=120s

# --- 1. ALLOWED: named in-cluster service (Postgres :5432) must SUCCEED ----------
assert_egress_allowed "${NS}" "${PROBE_POD}" "${PG_HOST}" "${PG_PORT}" 5 \
  "named in-cluster service egress (worker -> ${PG_HOST}:${PG_PORT})"

# --- 2. DENIED: arbitrary external egress must be BLOCKED ------------------------
# The deterministic deny bite (ADR-0041 §3): an external destination that is NOT
# the device mgmt subnet and NOT a named service is unreachable. We retry a few
# times so a slow dataplane-program does not read a transient block as the result,
# but a PERSISTENTLY-reachable external target after default-deny is a HARD failure
# (the assert helper records that as a fail).
assert_egress_blocked "${NS}" "${PROBE_POD}" "${DENY_HOST}" "${DENY_PORT}" 5 \
  "arbitrary external egress (worker -> ${DENY_HOST}:${DENY_PORT}) must be denied"

echo "== collector egress assertion complete: $(assert_failures) failure(s) =="
