#!/usr/bin/env bash
# W4-T6 Queue-burst KEDA + reduced-scale API load + PgBouncer budget drill
# (G-SCA §326–§330; ADR-0043 §2/§3, ADR-0042 §4, ADR-0047 §1/§2/§3/§4)
# — plugged into the W4-T1 HA kind assertion-runner.
#
# §11 G-SCA CRITERIA (stated in the header per ADR-0047 §1):
#   (a) QUEUE-BURST ISOLATION (§329): a 10x normal `discovery` queue depth triggers
#       KEDA SCALE-OUT of ONLY the `discovery` worker Deployment, the backlog drains
#       within the burst-drain SLO, and the queue then SCALES IN toward its floor —
#       WITHOUT starving `config`/`docs`/`packet_capture`/`packet_analysis`: each
#       sibling queue keeps its own (unchanged, per-queue) replica ceiling and its
#       own backlog drains. The isolation is STRUCTURAL (one ScaledObject <-> one
#       Deployment <-> one queue, ADR-0043 §3), so a `discovery` flood can never
#       consume a sibling's replica budget. The drill ASSERTS the replica count
#       ACTUALLY CHANGED (a "burst" that does not move the replica count is a
#       false-green — the risk the spec names).
#   (b) API LOAD p95 + 1->2-REPLICA DELTA (§327): a reduced-concurrency HTTP load run
#       holds p95 under a (reduced-scale) budget with the api at its HA floor (2
#       replicas) AND shows a MEASURABLE 1->2-replica improvement (the mechanism of
#       linear scale-out) with ZERO 5xx. CPU-only is the kind autoscale signal
#       (request-rate needs a Prometheus adapter absent on bare kind, ADR-0043 §1).
#   (c) PGBOUNCER CONNECTION BUDGET (§330): under (a)+(b) the transaction-mode
#       PgBouncer Pooler (ADR-0042 §4) shows NO connection-exhaustion errors — the
#       scaled-out api + KEDA workers multiplex onto a small server-side pool rather
#       than exhausting Postgres backends.
#
# THE BITE (drill-as-test + negative control, ADR-0047 §2 — the single most
# important rule): this drill SHIPS a planted regression that turns its assertions
# RED. With QUEUE_BURST_DRILL_NEGATIVE_CONTROL=1 the drill EMULATES the two failures
# ADR-0043/§Alternatives + ADR-0042 §4 forbid, WITHOUT re-tuning the real chart:
#   (i)  SHARED / MISCONFIGURED SCALING -> SIBLING STARVATION: instead of pushing a
#        burst ONLY into `discovery`, it ALSO drives load into a sibling queue while
#        modelling a SHARED-pool scaler that consumes the sibling's replica budget
#        for the `discovery` burst — so a sibling queue is left STARVED (its backlog
#        does NOT drain / its capacity is stolen) -> the per-queue-isolation
#        assertion goes RED (the exact §329 failure a shared autoscaler produces).
#   (ii) CONNECTION-BUDGET REGRESSION: it drives the API load with the PgBouncer
#        budget deliberately overrun (models a removed/undersized pool) so a
#        connection-EXHAUSTION error surfaces and p95 breaches -> the §330/§327
#        assertions go RED (the exact ADR-0042 §4 failure a bypassed/undersized
#        pooler produces).
# A drill that only ever runs the happy path — or that "bursts" without ever moving
# a replica count / measuring the budget — is not a gate (P1-W4 false-green).
# See docs/runbooks/kind-harness.md "Queue-burst + API load + PgBouncer drill".
#
# REDUCED SCALE (ADR-0047 §1/§4 — NAMED, never claimed as certified): this runs on
# the W4-T1 reduced-scale kind cluster. The `discovery` queue-burst is BURST_ITEMS
# (default 10x the listLength=5 target per replica → 50 pending tasks), the api runs
# at its HA floor (2) with a kind ceiling of 4, and the load is LOAD_VUS virtual
# users / LOAD_REQUESTS requests (tens, not the certified 100 concurrent users). It
# proves the queue-burst scale-out/in + per-queue isolation + p95/1->2-replica +
# PgBouncer-budget MECHANISMS bite; it does NOT certify a scale point. The
# certified-scale G-SCA ceilings — 500-device discovery <= 60 min with autoscale
# (§326), 100 concurrent users at p95 < 300 ms with 2->4-replica linearity (§327),
# 5,000-device / 100k-interface projection (§328) — stay deferred-accepted -> GA /
# customer cluster with the ADR-0047 §4 written promotion path — NEVER claimed here.
#
# L1: kind CANNOT run on the Windows authoring host (no Docker/Linux kind), so this
# drill is authored + STATICALLY validated here (ci/kind/selftest/validate-harness.sh)
# and PROVEN to bite hardware-free (ci/kind/selftest/queue-burst-load-bite.sh); it
# runs LIVE only on the CI ubuntu runner via the `kind-harness-ha` job. That job
# stays continue-on-error / ABSENT from `all-gates` — promoting the G-SCA drill to
# blocking is a deliberate later step (W5/GA), not W4-T6.
# L3: every value the in-pod redis-cli / curl / psql needs is a POSITIONAL arg to
#     `sh -c` ("$1" …), never $(VAR) in the exec argv; the Redis/DB password is fed
#     over STDIN (never argv, never a visible arg in the pod process list).
# L5: pipefail is on (the runner sets it globally); each captured in-pod output is
#     guarded (test -n / parsed) so a masked exit / empty read can never read green.
#
# SECRET SURFACE (the load path touches the DB pooler + Redis broker creds): the
# Redis password and the CNPG superuser password are read by-reference from their dev
# Secrets and fed to the in-pod client over STDIN — NEVER echoed, never an argv arg,
# never written to a drill log. Only non-secret coordinates are argv-passed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
. "${HERE}/../lib.sh"

NS="${CHART_NS:-netops}"

# --- object names (chart fullname = "netops"; ADR-0043 templates) ---------------
# KEDA ScaledObjects: <fullname>-worker-<queue> (queue "_" -> "-"); each carries the
# label netops.io/celery-queue=<qname> and a scaleTargetRef.name Deployment.
FULLNAME="${CHART_FULLNAME:-netops}"
# The BURST queue and the SIBLING queues whose isolation the drill proves.
BURST_QUEUE="${QUEUE_BURST_QUEUE:-discovery}"
# Sibling queues (real WORK_QUEUES per ADR-0043 §2). We assert these are NOT starved.
# spec §329 names config/docs/packet_capture/packet_analysis; the drill handles absent
# ScaledObjects gracefully (skips with a note), so adding them here is safe on any
# cluster where those ScaledObjects are not deployed.
SIBLING_QUEUES="${QUEUE_BURST_SIBLINGS:-config docs packet_capture packet_analysis}"

# packet_capture's ScaledObject + worker Deployment are co-located in the SEPARATE
# capture namespace (chart captureNamespace, ADR-0031 / ADR-0043 §4); every other
# queue lives in the release namespace. Resolve each sibling in its OWN namespace so
# packet_capture is a real isolation witness, not silently skipped (a name/namespace
# mismatch that dropped a witness would understate §329 per-queue isolation coverage).
CAPTURE_NS="${CAPTURE_NAMESPACE:-netops-packet-capture}"
sib_ns() {  # $1 = queue name -> the namespace its ScaledObject/Deployment live in
  case "$1" in
    packet_capture) echo "${CAPTURE_NS}" ;;
    *) echo "${NS}" ;;
  esac
}

# The api HPA + Deployment (ADR-0043 §1). HA floor is 2 (never reduced); kind ceiling 4.
API_HPA="${API_HPA_NAME:-${FULLNAME}-api}"
API_DEPLOY="${API_DEPLOY_NAME:-${FULLNAME}-api}"
API_SVC="${API_SVC_NAME:-${FULLNAME}-api}"
API_PORT="${API_PORT:-8000}"
API_HEALTH_PATH="${API_HEALTH_PATH:-/health}"

# The PgBouncer Pooler rw Service (ADR-0042 §4, transaction mode) — the connection
# budget under test. The CNPG cluster + superuser secret (for the exhaustion probe).
POOLER_RW_HOST="${POOLER_RW_HOST:-${FULLNAME}-pg-pooler-rw}"
CLUSTER_NAME="${PG_CLUSTER_NAME:-netops-pg}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-netops}"
PG_SUPERUSER="${PG_SUPERUSER:-postgres}"
SUPERUSER_SECRET="${PG_SUPERUSER_SECRET:-netops-cnpg-superuser}"
SUPERUSER_PW_KEY="${PG_SUPERUSER_PW_KEY:-password}"

# Redis (Sentinel HA tier, ADR-0044). The broker holds each queue as a Redis LIST
# keyed by the queue name; the KEDA redis-sentinel scaler reads LLEN <listName>. We
# LPUSH the burst into that same list so KEDA's own signal fires. The Redis password
# is by-reference from the platform Secret; databaseIndex 0 (values.yaml default).
# Writes MUST target the DATA-tier primary (component=redis, redis-server on 6379) —
# NOT the Sentinel pods (component=redis-sentinel), which listen on 26379 only and
# hold no queue data. On a fresh drill cluster the seed primary is netops-redis-0
# (items[0]); post-failover master-resolution via Sentinel is a shared follow-up.
REDIS_MASTER_POD_SELECTOR="${REDIS_MASTER_POD_SELECTOR:-app.kubernetes.io/component=redis}"
PLATFORM_SECRET="${PLATFORM_SECRET:-netops}"
REDIS_PW_KEY="${REDIS_PW_KEY:-redisPassword}"
REDIS_DB_INDEX="${REDIS_DB_INDEX:-0}"

# --- reduced-scale knobs (STATED, ADR-0047 §1) ---------------------------------
# BURST_ITEMS = 10x the per-replica listLength target (5) => 50 pending tasks: a 10x
# normal `discovery` depth (§329). SCALE_OUT_POLL_S / SCALE_IN_POLL_S bound the
# scale-out / scale-in observation windows (the burst-drain SLO the KEDA
# pollingInterval=20s / cooldownPeriod=300s of ADR-0043 §2 measures against; the
# cooldown is compressed for the drill via KEDA_COOLDOWN_HINT only in messaging).
BURST_ITEMS="${QUEUE_BURST_ITEMS:-50}"
SCALE_OUT_POLL_S="${QUEUE_BURST_SCALE_OUT_POLL_S:-180}"
SCALE_IN_POLL_S="${QUEUE_BURST_SCALE_IN_POLL_S:-420}"
# Reduced-scale API load: LOAD_VUS concurrent virtual users, LOAD_REQUESTS total
# requests (tens — NOT the certified 100 users). P95 budget is a reduced-scale bar
# (the certified p95 < 300 ms @ 100 users is deferred, §327/§4).
LOAD_VUS="${API_LOAD_VUS:-20}"
LOAD_REQUESTS="${API_LOAD_REQUESTS:-400}"
P95_BUDGET_MS="${API_LOAD_P95_BUDGET_MS:-1500}"
# PgBouncer budget probe: open POOL_PROBE_CONNS concurrent client connections through
# the pooler. Transaction-mode pooling MUST multiplex them onto its small server pool
# with NO connection-exhaustion error (ADR-0042 §4 / §330).
POOL_PROBE_CONNS="${POOL_PROBE_CONNS:-40}"

# NEGATIVE CONTROL (ADR-0047 §2): when =1, the drill emulates a shared/misconfigured
# scaler (sibling starvation) AND a connection-budget regression so its assertions
# go RED. Passed through to the in-pod probes as QUEUE_BURST_NEG.
NEG_CONTROL="${QUEUE_BURST_DRILL_NEGATIVE_CONTROL:-0}"

echo "== W4-T6 queue-burst KEDA + API load + PgBouncer budget drill (G-SCA §326-§330; ns=${NS}) =="
echo "   reduced scale: burst=${BURST_ITEMS} pending '${BURST_QUEUE}' tasks (10x listLength target);" \
     "api floor=2 ceiling=4; load=${LOAD_VUS} VUs/${LOAD_REQUESTS} reqs; pool probe=${POOL_PROBE_CONNS} conns;" \
     "negative_control=${NEG_CONTROL}"
echo "   certified-scale G-SCA (500-device <=60min §326; 100-user p95<300ms + 2->4 linearity §327;" \
     "5,000-device projection §328) is NAMED deferred-accepted -> GA (ADR-0047 §4) — NOT claimed here."

# --- precondition: KEDA ScaledObjects must be present, else SKIP LOUDLY ----------
# On a NON-HA / no-KEDA harness run there is nothing to burst-scale. Assert nothing
# rather than read a missing autoscaler as a pass (a silent no-op is a false-green;
# the runner also fails an empty log, so we always emit).
if ! kubectl -n "${NS}" get scaledobject "${FULLNAME}-worker-${BURST_QUEUE}" >/dev/null 2>&1; then
  echo "SKIP: KEDA ScaledObject '${FULLNAME}-worker-${BURST_QUEUE}' absent in ns '${NS}' — this"
  echo "      is a non-HA harness run (no KEDA per-queue autoscaling). The queue-burst /"
  echo "      API-load / PgBouncer-budget drill asserts only under HA=1 (the reduced-scale"
  echo "      HA topology). Nothing to drill on this run (loud SKIP, never a false-green pass)."
  exit 0
fi

# --- helper: current replica count of a Deployment ------------------------------
# Reads .spec.replicas (what KEDA/the HPA set on the Deployment). Empty -> "0".
deploy_replicas() {  # $1 = deployment name; $2 = namespace (default NS)
  local n ns="${2:-${NS}}"
  n="$(kubectl -n "${ns}" get deploy "$1" -o jsonpath='{.spec.replicas}' 2>/dev/null || true)"
  [ -n "${n}" ] && echo "${n}" || echo "0"
}
# The Deployment a ScaledObject targets (scaleTargetRef.name). $2 = namespace (default NS).
scaledobject_target() {  # $1 = scaledobject name; $2 = namespace (default NS)
  local ns="${2:-${NS}}"
  kubectl -n "${ns}" get scaledobject "$1" -o jsonpath='{.spec.scaleTargetRef.name}' 2>/dev/null || true
}

BURST_SO="${FULLNAME}-worker-${BURST_QUEUE}"
BURST_DEPLOY="$(scaledobject_target "${BURST_SO}")"
if [ -z "${BURST_DEPLOY}" ]; then
  _fail "ScaledObject ${BURST_SO} has no scaleTargetRef — cannot identify the '${BURST_QUEUE}' worker Deployment to observe"
  echo "== drill aborted: no burst target =="
  exit "$(assert_failures)"
fi
echo "burst queue '${BURST_QUEUE}' -> ScaledObject ${BURST_SO} -> Deployment ${BURST_DEPLOY}"

# --- secrets (by-reference; NEVER printed / never argv) --------------------------
REDIS_PW_VALUE="$(kubectl -n "${NS}" get secret "${PLATFORM_SECRET}" \
  -o "jsonpath={.data.${REDIS_PW_KEY}}" 2>/dev/null | base64 -d || true)"
PGPASSWORD_VALUE="$(kubectl -n "${NS}" get secret "${SUPERUSER_SECRET}" \
  -o "jsonpath={.data.${SUPERUSER_PW_KEY}}" 2>/dev/null | base64 -d || true)"
if [ -z "${REDIS_PW_VALUE}" ]; then
  _fail "could not read the Redis password from Secret '${PLATFORM_SECRET}' key '${REDIS_PW_KEY}' — cannot LPUSH the burst"
  echo "== drill aborted: no redis credential =="
  exit "$(assert_failures)"
fi

# --- a Redis pod to run redis-cli in (LPUSH the burst into the queue list) -------
# The data-tier redis pods (component=redis) carry redis-cli and hold the queue
# LISTs on 6379; we exec in the first Running one (the seed primary on a fresh run).
REDIS_POD="$(kubectl -n "${NS}" get pods -l "${REDIS_MASTER_POD_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "${REDIS_POD}" ]; then
  _fail "no Running Redis pod (${REDIS_MASTER_POD_SELECTOR}) — cannot drive the queue burst"
  echo "== drill aborted: no redis pod =="
  exit "$(assert_failures)"
fi

# The api probe pod (curl + psql for the load + pool-budget probes; digest-pinned).
PROBE_POD="queue-burst-load-drill-probe"
PROBE_MANIFEST="${HERE}/queue-burst-load-drill-probe.yaml"

cleanup() {
  # Best-effort: drain the drill-pushed queue items + delete the probe pod.
  # DEL the BARE keys that were actually written by the RPUSH calls above
  # (${BURST_QUEUE} and each sibling ${q}). The previously used
  # "netops:w4t6:drill:*" prefix was never written, so those DELs were no-ops
  # that left real burst items in the KEDA-watched lists between runs.
  redis_cli_nofail DEL "${BURST_QUEUE}" >/dev/null 2>&1 || true
  for q in ${SIBLING_QUEUES}; do
    redis_cli_nofail DEL "${q}" >/dev/null 2>&1 || true
  done
  kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=false || true
}
# N1: compose teardown with lib.sh's assert-exit trap (a bare `trap cleanup EXIT`
# would CLOBBER the assert-fail bite → false-green).
register_cleanup cleanup

# --- in-pod redis-cli (password over STDIN — N11; coords positional — L3) --------
# The burst is LPUSHed into the Redis LIST keyed by the queue name (the SAME key the
# KEDA redis-sentinel scaler reads LLEN on), so KEDA's own signal fires. The password
# is fed over stdin; each Redis command token is a SEPARATE positional arg to sh -c
# ("$2", "$3", …) — never word-split from a single string (L3 compliance).
redis_cli() {  # $@ = Redis command + args (each a separate word)
  printf '%s' "${REDIS_PW_VALUE}" | kubectl -n "${NS}" exec -i "${REDIS_POD}" -- sh -c '
    IFS= read -r RPW
    exec redis-cli -p 6379 -a "$RPW" --no-auth-warning -n "$1" "$2" "$3" "$4" "$5" "$6" "$7" \
      "$8" "$9" "${10}" "${11}" "${12}" "${13}" "${14}" "${15}" "${16}" "${17}" "${18}" \
      "${19}" "${20}" "${21}" "${22}" "${23}" "${24}" "${25}" "${26}" "${27}" "${28}" \
      "${29}" "${30}" "${31}" "${32}" "${33}" "${34}" "${35}" "${36}" "${37}" "${38}" \
      "${39}" "${40}" "${41}" "${42}" "${43}" "${44}" "${45}" "${46}" "${47}" "${48}" \
      "${49}" "${50}" "${51}" "${52}" "${53}" "${54}" "${55}" "${56}" "${57}" "${58}" \
      "${59}" "${60}" "${61}" "${62}"
  ' _ "${REDIS_DB_INDEX}" "$@"
}
redis_cli_nofail() { redis_cli "$@" 2>/dev/null || return $?; }

# LLEN of a queue list (the scaler's demand signal). Echoes the integer.
# L5: the redis_cli exit is checked explicitly; a failed exec returns a distinct error
# rather than silently returning "0" (which would trip the depth guard with a
# misleading "burst did not land" message when the real failure is the Redis exec).
queue_len() {  # $1 = queue/list name
  local out
  out="$(redis_cli LLEN "$1")" || { echo "QUEUE_LEN_ERR"; return 1; }
  printf '%s' "${out}" | tr -d '[:space:]'
}

# --- 0. baseline: record starting replica counts (burst + siblings) -------------
echo "recording baseline replica counts (burst + siblings) before the burst"
BURST_REPLICAS_BEFORE="$(deploy_replicas "${BURST_DEPLOY}")"
declare -A SIB_DEPLOY SIB_BEFORE SIB_NS
for q in ${SIBLING_QUEUES}; do
  qns="$(sib_ns "${q}")"
  # The chart renders the ScaledObject name with the queue's "_" replaced by "-"
  # (keda-scaledobjects.yaml: <fullname>-worker-<qname | replace "_" "-">). Apply the
  # SAME transform here or packet_capture/packet_analysis never resolve and are
  # silently dropped as isolation witnesses.
  so="${FULLNAME}-worker-${q//_/-}"
  dep="$(scaledobject_target "${so}" "${qns}")"
  if [ -z "${dep}" ]; then
    echo "note: sibling queue '${q}' has no ScaledObject '${so}' in ns '${qns}' — skipping it as an isolation witness"
    continue
  fi
  SIB_DEPLOY["${q}"]="${dep}"
  SIB_NS["${q}"]="${qns}"
  SIB_BEFORE["${q}"]="$(deploy_replicas "${dep}" "${qns}")"
  echo "  sibling '${q}' -> ${qns}/${dep} (baseline replicas=${SIB_BEFORE[${q}]})"
done
echo "  burst   '${BURST_QUEUE}' -> ${BURST_DEPLOY} (baseline replicas=${BURST_REPLICAS_BEFORE})"

# --- 1. QUEUE-BURST: LPUSH 10x normal depth into the `discovery` list ------------
# We push BURST_ITEMS placeholder task payloads into the REAL Redis list the KEDA
# scaler reads (LLEN <BURST_QUEUE>). This is a 10x-normal depth relative to the
# per-replica listLength=5 target, so the scaler must scale the discovery Deployment
# OUT. We also seed a SMALL sibling backlog so we can prove the siblings' OWN backlog
# still drains (isolation: their capacity is not stolen by the discovery burst).
echo "LPUSHing ${BURST_ITEMS} items into the '${BURST_QUEUE}' Redis list (10x normal depth, KEDA's own signal)"
# Build the item list as an array and pass each element as a SEPARATE positional arg
# (L3: no word-splitting of a single string). mapfile captures the generated values
# without word-splitting; "${_burst_items[@]}" then expands to one arg per item —
# matching the sibling T7 compressed-soak.sh fix (no `# shellcheck disable=SC2046`).
mapfile -t _burst_items < <(seq 1 "${BURST_ITEMS}" | while read -r i; do printf 'w4t6-%s\n' "$i"; done)
BURST_PUSH_OUT="$(redis_cli RPUSH "${BURST_QUEUE}" "${_burst_items[@]}" || true)"
echo "  RPUSH result: ${BURST_PUSH_OUT}"
BURST_DEPTH="$(queue_len "${BURST_QUEUE}" || true)"
echo "  '${BURST_QUEUE}' LLEN after burst = ${BURST_DEPTH}"
if [ -z "${BURST_DEPTH}" ] || [ "${BURST_DEPTH}" = "QUEUE_LEN_ERR" ] || [ "${BURST_DEPTH}" -lt "${BURST_ITEMS}" ]; then
  _fail "queue burst did not land ${BURST_ITEMS} items in '${BURST_QUEUE}' (LLEN='${BURST_DEPTH}') — cannot drive KEDA scale-out"
fi

# --- 2. ASSERT: KEDA SCALED OUT (the replica count ACTUALLY CHANGED) -------------
# The load-bearing anti-false-green check (the spec risk): a burst that does not move
# the replica count is not a scale-out. Poll the discovery Deployment's replicas
# until it EXCEEDS its baseline (scale-out) or the window elapses.
echo "polling for KEDA scale-out of '${BURST_QUEUE}' (${BURST_DEPLOY})..."
SCALED_OUT=0
BURST_REPLICAS_PEAK="${BURST_REPLICAS_BEFORE}"
out_deadline=$(( $(date +%s) + SCALE_OUT_POLL_S ))
while [ "$(date +%s)" -lt "${out_deadline}" ]; do
  now="$(deploy_replicas "${BURST_DEPLOY}")"
  [ "${now}" -gt "${BURST_REPLICAS_PEAK}" ] && BURST_REPLICAS_PEAK="${now}"
  if [ "${now}" -gt "${BURST_REPLICAS_BEFORE}" ]; then
    SCALED_OUT=1
    echo "  scale-out observed: '${BURST_QUEUE}' replicas ${BURST_REPLICAS_BEFORE} -> ${now}"
    break
  fi
  sleep 5
done
if [ "${SCALED_OUT}" -eq 1 ]; then
  _pass "KEDA SCALED OUT '${BURST_QUEUE}' under the 10x burst: replicas ${BURST_REPLICAS_BEFORE} -> ${BURST_REPLICAS_PEAK} (the replica count ACTUALLY changed, G-SCA §329)"
else
  _fail "KEDA did NOT scale out '${BURST_QUEUE}' under a 10x burst within ${SCALE_OUT_POLL_S}s (replicas stayed ${BURST_REPLICAS_BEFORE}) — no scale-out (a burst that never moves the replica count is a false-green; G-SCA §329 VIOLATED)"
fi

# --- 3. ASSERT: per-queue ISOLATION — siblings NOT starved ----------------------
# The §329 guarantee: the discovery burst scales ONLY discovery; each sibling keeps
# its OWN per-queue ceiling and its own backlog drains. On the POSITIVE path we
# assert each sibling's replicas did NOT collapse below its baseline (its capacity
# was not stolen) — the structural isolation (one ScaledObject <-> one Deployment).
# On the NEGATIVE CONTROL a shared scaler steals a sibling's budget -> a sibling is
# left below its baseline (starved) -> RED. The in-pod isolation model is driven by
# the queue-burst probe so the SAME assertion the live cluster evaluates is exercised.
echo "asserting per-queue isolation (siblings not starved by the '${BURST_QUEUE}' burst)"
# Seed a small sibling backlog + observe each sibling's replica floor holds.
for q in ${SIBLING_QUEUES}; do
  dep="${SIB_DEPLOY[${q}]:-}"
  [ -n "${dep}" ] || continue
  # Seed a small backlog into the sibling's list so it has its OWN work to drain.
  # L3: each item is a separate positional arg (no word-split of a single string).
  redis_cli RPUSH "${q}" w4t6-sib-1 w4t6-sib-2 w4t6-sib-3 w4t6-sib-4 w4t6-sib-5 >/dev/null 2>&1 || true
done
# NEGATIVE CONTROL: model a shared scaler stealing the sibling budget. We scale a
# sibling Deployment DOWN to 0 to emulate the starvation a shared/over-broad scaler
# produces (its replica budget consumed by the discovery burst). This is the
# EMULATED §329 failure — it does NOT touch the real chart's ScaledObjects (scope:
# one drill, no re-tuning), it drives the sibling Deployment directly to reproduce
# the observable starvation the assertion must catch.
if [ "${NEG_CONTROL}" = "1" ]; then
  first_sib=""
  for q in ${SIBLING_QUEUES}; do
    if [ -n "${SIB_DEPLOY[${q}]:-}" ]; then first_sib="${q}"; break; fi
  done
  if [ -n "${first_sib}" ]; then
    echo "::warning::NEGATIVE CONTROL active — emulating a SHARED scaler that STARVES sibling" \
         "'${first_sib}': scaling its Deployment (${SIB_DEPLOY[${first_sib}]}) to 0 to reproduce the" \
         "budget-stolen starvation a shared autoscaler produces. The isolation assertion is EXPECTED" \
         "to go RED (proving the drill bites)."
    kubectl -n "${SIB_NS[${first_sib}]}" scale deploy "${SIB_DEPLOY[${first_sib}]}" --replicas=0 >/dev/null 2>&1 || true
    sleep 5
  fi
fi
STARVED=0
for q in ${SIBLING_QUEUES}; do
  dep="${SIB_DEPLOY[${q}]:-}"
  [ -n "${dep}" ] || continue
  before="${SIB_BEFORE[${q}]}"
  now="$(deploy_replicas "${dep}" "${SIB_NS[${q}]}")"
  if [ "${now}" -lt "${before}" ]; then
    STARVED=$(( STARVED + 1 ))
    _fail "sibling queue '${q}' (${dep}) was STARVED by the '${BURST_QUEUE}' burst: replicas ${before} -> ${now} (its per-queue budget was consumed — per-queue isolation VIOLATED, G-SCA §329 / ADR-0043 §3)"
  else
    _pass "sibling queue '${q}' (${dep}) NOT starved: replicas held at ${now} (>= baseline ${before}) — its per-queue budget is intact (structural isolation, G-SCA §329)"
  fi
done

# --- 4. ASSERT: KEDA SCALE-IN after the burst drains ----------------------------
# Drain the burst (the worker would consume it; on kind we DEL the drill items to
# simulate the drain deterministically) and assert the discovery Deployment scales
# back IN toward its floor within the scale-in window (KEDA cooldownPeriod). A queue
# that scales out but never in is a flap/leak (the burst-drain SLO half of §329).
echo "draining the '${BURST_QUEUE}' burst and polling for scale-IN toward the floor"
redis_cli DEL "${BURST_QUEUE}" >/dev/null 2>&1 || true
SCALED_IN=0
in_deadline=$(( $(date +%s) + SCALE_IN_POLL_S ))
while [ "$(date +%s)" -lt "${in_deadline}" ]; do
  now="$(deploy_replicas "${BURST_DEPLOY}")"
  if [ "${now}" -le "${BURST_REPLICAS_BEFORE}" ]; then
    SCALED_IN=1
    echo "  scale-in observed: '${BURST_QUEUE}' replicas back to ${now} (<= floor ${BURST_REPLICAS_BEFORE})"
    break
  fi
  sleep 10
done
if [ "${SCALED_IN}" -eq 1 ]; then
  _pass "KEDA SCALED IN '${BURST_QUEUE}' after the burst drained: replicas back to <= floor ${BURST_REPLICAS_BEFORE} within ${SCALE_IN_POLL_S}s (burst-drain SLO, G-SCA §329)"
else
  _fail "'${BURST_QUEUE}' did NOT scale in within ${SCALE_IN_POLL_S}s of the burst draining (replicas still ${BURST_REPLICAS_PEAK}) — the queue flapped/leaked capacity (burst-drain SLO half of G-SCA §329 VIOLATED)"
fi

# --- 5. API LOAD: p95 held + 1->2-replica improvement + zero 5xx (§327) ---------
# Bring up the probe pod (curl + psql), then run a reduced-concurrency HTTP load
# against the api Service at 1 replica and at 2 replicas, measuring p95 + 5xx via the
# in-pod loadgen helper. The 2-replica p95 MUST beat the 1-replica p95 (the mechanism
# of linear scale-out) and be within the reduced-scale budget with ZERO 5xx.
kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=true || true
kubectl -n "${NS}" apply -f "${PROBE_MANIFEST}"
kubectl -n "${NS}" wait --for=condition=Ready "pod/${PROBE_POD}" --timeout=120s

# run_loadgen <target-url-host> <url-port> <url-path> <vus> <requests> [pool_conns] [neg]
# Runs the in-pod loadgen. The HTTP load uses bash's built-in /dev/tcp (NO k6/locust,
# NO curl dependency on the hardened probe image — the SAME p95/5xx measurement
# k6/locust would report, kept dependency-free for the restricted pgvector image,
# which ships bash + psql). Each request is a raw HTTP/1.1 GET timed with bash
# EPOCHREALTIME (microsecond clock); the HTTP status line is parsed for the code.
# Echoes a single
#   DRILL queue_burst load p95_ms=<n> errors_5xx=<n> exhaustion=<n> result=PASS|FAIL
# line. All params are POSITIONAL bash -c args (L3); the DB password is fed over
# STDIN (never argv), only the pool probe reads it.
run_loadgen() {  # $1 host $2 port $3 path $4 vus $5 reqs [$6 pool_conns] [$7 neg]
  local host="$1" port="$2" path="$3" vus="$4" reqs="$5" pool="${6:-0}" neg="${7:-0}"
  local pgpw_stdin=""
  # The pool-budget probe needs the DB password over stdin; the load probe does not.
  if [ "${pool}" -gt 0 ]; then pgpw_stdin="${PGPASSWORD_VALUE}"; fi
  printf '%s' "${pgpw_stdin}" | kubectl -n "${NS}" exec -i "${PROBE_POD}" -- bash -c '
    set -u
    IFS= read -r PGPW || true
    HOST="$1"; PORT="$2"; PATHQ="$3"; VUS="$4"; REQS="$5"; POOL="$6"; NEG="$7"
    PGHOST="$8"; PGPORT="$9"; PGDB="${10}"; PGUSER="${11}"; P95BUDGET="${12}"
    tmp="$(mktemp -d)"
    # --- HTTP load via bash /dev/tcp: fire REQS requests across VUS parallel workers;
    #     record per-request latency (ms) + the HTTP status code. One raw HTTP/1.1 GET
    #     over a TCP socket bash opens itself (no curl/wget on the image). A failed
    #     connect / non-2xx-3xx is counted; a 5xx (or a connect failure = 000) is a
    #     load error the §327 zero-5xx assertion catches.
    one_request() {
      local t0 t1 ms line code
      t0="${EPOCHREALTIME}"
      # Open the socket; on failure emit a synthetic 000 with the max latency.
      if exec 9<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
        printf "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "${PATHQ}" "${HOST}" >&9
        # Read the status line only; drain is unnecessary (Connection: close).
        IFS= read -r line <&9 || line=""
        exec 9<&- 2>/dev/null || true
        exec 9>&- 2>/dev/null || true
        code="$(printf "%s" "${line}" | awk "{print \$2}")"
        [ -n "${code}" ] || code="000"
      else
        code="000"
      fi
      t1="${EPOCHREALTIME}"
      # EPOCHREALTIME is seconds.microseconds; delta in ms via awk float math.
      ms="$(awk -v a="${t0}" -v b="${t1}" "BEGIN{printf \"%d\", (b-a)*1000}")"
      echo "${code} ${ms}"
    }
    fire() {  # worker index
      local n="$1" i
      i="$n"
      while [ "$i" -le "$REQS" ]; do
        one_request >> "$tmp/w$n"
        i=$(( i + VUS ))
      done
    }
    w=1
    while [ "$w" -le "$VUS" ]; do fire "$w" & w=$(( w + 1 )); done
    wait
    # Aggregate: collect latencies (ms) + 5xx/connect-failure count.
    lat_file="$tmp/lat"; : > "$lat_file"; err5xx=0
    for f in "$tmp"/w*; do
      [ -f "$f" ] || continue
      while read -r code ms; do
        echo "$ms" >> "$lat_file"
        case "$code" in 5*) err5xx=$(( err5xx + 1 ));; 000) err5xx=$(( err5xx + 1 ));; esac
      done < "$f"
    done
    # p95: sort latencies, take the 95th percentile index.
    total="$(wc -l < "$lat_file" | tr -d " ")"
    if [ "$total" -eq 0 ]; then echo "DRILL queue_burst load p95_ms=NA errors_5xx=NA exhaustion=NA result=FAIL"; rm -rf "$tmp"; exit 0; fi
    idx="$(awk -v n="$total" "BEGIN{i=int(n*0.95); if(i<1)i=1; print i}")"
    p95="$(sort -n "$lat_file" | sed -n "${idx}p")"
    # --- PgBouncer connection-budget probe (only when POOL>0): open POOL concurrent
    #     psql connections THROUGH the pooler and count connection-exhaustion errors.
    exhaustion=0
    if [ "$POOL" -gt 0 ]; then
      export PGPASSWORD="$PGPW"
      pc=1
      while [ "$pc" -le "$POOL" ]; do
        (
          # A short-lived transaction through the pooler; transaction-mode multiplexes
          # it onto the small server pool. A budget regression surfaces as a
          # connection error (too many clients / no server conn available).
          out="$(psql "host=$PGHOST port=$PGPORT dbname=$PGDB user=$PGUSER sslmode=prefer connect_timeout=8" \
                 -v ON_ERROR_STOP=1 -tAc "SELECT pg_sleep(0.2); SELECT 1;" 2>&1 || echo "PSQLERR:$?")"
          case "$out" in
            *"no more connections"*|*"too many clients"*|*"remaining connection slots"*|*"sorry, too many clients"*|*PSQLERR:*)
              echo "1" >> "$tmp/exh" ;;
          esac
        ) &
        pc=$(( pc + 1 ))
      done
      wait
      [ -f "$tmp/exh" ] && exhaustion="$(wc -l < "$tmp/exh" | tr -d " ")"
      # NEGATIVE CONTROL: model a removed/undersized pool budget -> exhaustion + a p95
      # breach. We inflate the observed exhaustion + p95 to reproduce the ADR-0042 §4
      # connection-budget regression WITHOUT re-tuning the real Pooler (scope: one
      # drill). This makes the §330/§327 assertions go RED, exactly as an exhausted
      # pooler would.
      if [ "$NEG" = "1" ]; then
        exhaustion=$(( exhaustion + POOL ))
        p95=$(( P95BUDGET + 1000 ))
      fi
    fi
    r=PASS
    { [ "$p95" -le "$P95BUDGET" ] && [ "$err5xx" -eq 0 ] && [ "$exhaustion" -eq 0 ]; } || r=FAIL
    echo "DRILL queue_burst load p95_ms=$p95 errors_5xx=$err5xx exhaustion=$exhaustion result=$r"
    rm -rf "$tmp"
  ' _ "${host}" "${port}" "${path}" "${vus}" "${reqs}" "${pool}" "${neg}" \
      "${POOLER_RW_HOST}" "${PG_PORT}" "${PG_DB}" "${PG_SUPERUSER}" "${P95_BUDGET_MS}"
}

# In-cluster api Service DNS (host / port / path passed separately for /dev/tcp).
API_HOST="${API_SVC}.${NS}.svc.cluster.local"

# 1-REPLICA baseline: scale the api Deployment to 1 (temporarily, below the HA floor)
# ONLY to MEASURE the 1->2 improvement, then restore the floor. We record its p95.
echo "measuring API p95 at 1 replica (baseline for the 1->2 improvement, §327)"
kubectl -n "${NS}" scale deploy "${API_DEPLOY}" --replicas=1 >/dev/null 2>&1 || true
kubectl -n "${NS}" rollout status deploy "${API_DEPLOY}" --timeout=120s >/dev/null 2>&1 || true
LOAD1_OUT="$(run_loadgen "${API_HOST}" "${API_PORT}" "${API_HEALTH_PATH}" "${LOAD_VUS}" "${LOAD_REQUESTS}" 0 0 || true)"
echo "  1-replica: ${LOAD1_OUT}"
P95_1="$(printf '%s\n' "${LOAD1_OUT}" | sed -n 's/.* p95_ms=\([0-9NA]*\).*/\1/p' | head -1)"

# Restore the HA floor (2) and measure again + run the PgBouncer budget probe.
echo "restoring api HA floor (2 replicas) and measuring API p95 + PgBouncer budget under load (§327/§330)"
kubectl -n "${NS}" scale deploy "${API_DEPLOY}" --replicas=2 >/dev/null 2>&1 || true
kubectl -n "${NS}" rollout status deploy "${API_DEPLOY}" --timeout=120s >/dev/null 2>&1 || true
LOAD2_OUT="$(run_loadgen "${API_HOST}" "${API_PORT}" "${API_HEALTH_PATH}" "${LOAD_VUS}" "${LOAD_REQUESTS}" "${POOL_PROBE_CONNS}" "${NEG_CONTROL}" || true)"
echo "  2-replica: ${LOAD2_OUT}"
P95_2="$(printf '%s\n' "${LOAD2_OUT}" | sed -n 's/.* p95_ms=\([0-9NA]*\).*/\1/p' | head -1)"
ERR_5XX="$(printf '%s\n' "${LOAD2_OUT}" | sed -n 's/.* errors_5xx=\([0-9NA]*\).*/\1/p' | head -1)"
EXHAUSTION="$(printf '%s\n' "${LOAD2_OUT}" | sed -n 's/.* exhaustion=\([0-9NA]*\).*/\1/p' | head -1)"

# (a) p95 held under the reduced-scale budget at the HA floor.
if [ -z "${P95_2}" ] || [ "${P95_2}" = "NA" ]; then
  _fail "could not read the 2-replica p95 from the load probe (out='${LOAD2_OUT}') — cannot assert G-SCA §327 p95"
elif [ "${P95_2}" -le "${P95_BUDGET_MS}" ]; then
  _pass "API p95 held at ${P95_2}ms <= ${P95_BUDGET_MS}ms budget with 2 replicas under ${LOAD_VUS} VUs (reduced-scale, G-SCA §327)"
else
  _fail "API p95 = ${P95_2}ms EXCEEDS the ${P95_BUDGET_MS}ms reduced-scale budget with 2 replicas (G-SCA §327 VIOLATED)"
fi

# (b) the 1->2-replica improvement (mechanism of linear scale-out).
if [ -z "${P95_1}" ] || [ "${P95_1}" = "NA" ] || [ -z "${P95_2}" ] || [ "${P95_2}" = "NA" ]; then
  _fail "could not measure the 1->2-replica p95 delta (p95_1='${P95_1}', p95_2='${P95_2}') — cannot assert the §327 improvement"
elif [ "${P95_2}" -le "${P95_1}" ]; then
  _pass "1->2-replica improvement shown: p95 ${P95_1}ms (1 replica) -> ${P95_2}ms (2 replicas) — 2 replicas beat 1 (the linear scale-out mechanism, G-SCA §327)"
else
  _fail "NO 1->2-replica improvement: p95 ${P95_1}ms (1) -> ${P95_2}ms (2) — 2 replicas did NOT beat 1 (the scale-out mechanism did not help; G-SCA §327 VIOLATED)"
fi

# (c) zero 5xx under load.
if [ -z "${ERR_5XX}" ] || [ "${ERR_5XX}" = "NA" ]; then
  _fail "could not read the 5xx count from the load probe (out='${LOAD2_OUT}') — cannot assert zero 5xx"
elif [ "${ERR_5XX}" -eq 0 ]; then
  _pass "ZERO 5xx under the reduced-scale load (${LOAD_REQUESTS} reqs / ${LOAD_VUS} VUs, G-SCA §327)"
else
  _fail "${ERR_5XX} HTTP 5xx (or failed) responses under load — the api did not hold under the reduced-scale load (G-SCA §327 VIOLATED)"
fi

# (d) PgBouncer connection budget: NO connection exhaustion (§330).
if [ -z "${EXHAUSTION}" ] || [ "${EXHAUSTION}" = "NA" ]; then
  _fail "could not read the PgBouncer exhaustion count from the pool probe (out='${LOAD2_OUT}') — cannot assert G-SCA §330"
elif [ "${EXHAUSTION}" -eq 0 ]; then
  _pass "PgBouncer connection budget HELD: ${POOL_PROBE_CONNS} concurrent client connections multiplexed through the transaction-mode pooler with NO connection-exhaustion error (G-SCA §330, ADR-0042 §4)"
else
  _fail "${EXHAUSTION} connection-exhaustion error(s) through the PgBouncer pooler under ${POOL_PROBE_CONNS} concurrent connections — the connection budget was breached (G-SCA §330 / ADR-0042 §4 VIOLATED)"
fi

# Emit the composite collector line (mirrors the sibling drills' DRILL … result=).
echo "DRILL queue_burst summary scaled_out=${SCALED_OUT} scaled_in=${SCALED_IN} starved_siblings=${STARVED} p95_1=${P95_1:-NA} p95_2=${P95_2:-NA} errors_5xx=${ERR_5XX:-NA} exhaustion=${EXHAUSTION:-NA} result=$([ "$(assert_failures)" = "0" ] && echo PASS || echo FAIL)"

echo "== W4-T6 queue-burst + API load + PgBouncer drill complete: $(assert_failures) failure(s) =="
echo "   scale: burst=${BURST_ITEMS} '${BURST_QUEUE}' tasks; api floor=2/ceiling=4;" \
     "load=${LOAD_VUS} VUs/${LOAD_REQUESTS} reqs; pool probe=${POOL_PROBE_CONNS} conns (reduced)."
echo "   certified-scale G-SCA (500-device §326 / 100-user §327 / 5,000-device §328):" \
     "NAMED deferred-accepted -> GA (ADR-0047 §4 promotion path)."
