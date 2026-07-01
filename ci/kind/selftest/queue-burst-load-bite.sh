#!/usr/bin/env bash
# EMPIRICAL, HARDWARE-FREE bite proof for the W4-T6 queue-burst + API load +
# PgBouncer budget drill (ADR-0047 §2 — the negative-control rule; ADR-0043 §3
# per-queue isolation, ADR-0042 §4 connection budget).
#
# WHY THIS EXISTS (L1 + ADR-0047 §2): the queue-burst/load drill (queue-burst-load.sh)
# runs LIVE only on a kind cluster with the KEDA + api-HPA + PgBouncer HA topology,
# which CANNOT run on the authoring host (Windows, no Docker/Linux kind). ADR-0047 §2
# nonetheless requires every drill's negative control be SHOWN to bite (plant → red →
# revert), never merely asserted. This self-test earns that proof WITHOUT a cluster:
# it runs the REAL queue-burst-load.sh check against a FAKE `kubectl` that simulates
# the ScaledObjects + Deployment replica counts + Redis LLEN + the in-pod loadgen /
# pool-budget probe, and asserts the OBSERVABLE polarity:
#   POSITIVE  — 10x `discovery` burst → the discovery Deployment scales OUT (replica
#               count grows) then scales IN; siblings NOT starved; API p95 held with
#               a 1->2-replica improvement + zero 5xx; PgBouncer no exhaustion
#               → drill GREEN (exit 0)
#   NEGATIVE  — QUEUE_BURST_DRILL_NEGATIVE_CONTROL=1 → a SHARED scaler STARVES a
#               sibling (its Deployment is scaled to 0) AND the PgBouncer budget is
#               overrun (connection exhaustion + p95 breach) → the isolation + §330 +
#               §327 assertions go RED → drill RED (exit != 0)
#   NO-SCALE-OUT — the burst Deployment's replica count never grows (models a
#               disabled/misconfigured KEDA trigger) → the "replica count actually
#               changed" assertion goes RED → drill RED (proving the scale-out step is
#               load-bearing, the exact spec risk: a burst that never moves a replica)
#
# The NEGATIVE / NO-SCALE-OUT scenarios are the planted regressions; POSITIVE is the
# revert-to-green. This is the executed plant→red→revert the live kind run would
# otherwise be the only place to observe (recorded here as a runnable proof; the live
# CI run corroborates it on the reduced-scale cluster).
#
# The fake kubectl interprets exactly the calls queue-burst-load.sh makes (get
# scaledobject, get deploy replicas, get secret, get pods -l redis, scale deploy,
# rollout status, apply/wait/delete pod, exec -i … redis-cli / bash loadgen). Replica
# state lives in a state dir the fake mutates: after the burst RPUSH the discovery
# Deployment's replicas GROW (models KEDA scale-out) unless NO_SCALE_OUT=1; a
# `scale deploy … --replicas=N` records N (so the api 1->2 and the negative-control
# sibling->0 are honoured); after the burst DEL the discovery Deployment scales back
# to its floor (models scale-in). The loadgen line's p95/errors/exhaustion flip on
# the negative-control flag the drill exports into the exec — so the SAME assertions
# the live cluster would evaluate are exercised.
#
# Run: ci/kind/selftest/queue-burst-load-bite.sh   (exits non-zero on any violation)
# CI:  the `kind-harness-ha` job runs this (no cluster needed — it is the local bite
#      proof for the live drill's negative control).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"
CHECK="${KIND_DIR}/assertions/checks/queue-burst-load.sh"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

if [ ! -f "${CHECK}" ]; then
  echo "::error::queue-burst-load.sh not found at ${CHECK}" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- the FAKE kubectl ----------------------------------------------------------
# A stand-in `kubectl` on PATH simulating just enough of the KEDA/HPA/PgBouncer HA
# topology for queue-burst-load.sh. State lives in $FAKE_STATE:
#   - <deploy>.replicas : the current .spec.replicas for a Deployment (seeded on
#     first read, updated by `scale deploy`, grown on burst, shrunk on drain).
#   - burst_pushed / burst_drained : markers set on the discovery RPUSH / DEL.
# Scenario knobs (env): NO_SCALE_OUT=1 keeps the discovery Deployment from growing
# after the burst (disabled trigger). The negative-control flag is exported by the
# drill into the loadgen exec (QUEUE_BURST_NEG via the drill's own $NEG arg); the fake
# reads it off the exec arg vector to flip the loadgen line.
FAKE_BIN="${WORK}/bin"
mkdir -p "${FAKE_BIN}"
cat > "${FAKE_BIN}/kubectl" <<'FAKE'
#!/usr/bin/env bash
# Fake kubectl for the queue-burst/load drill self-test. Deterministic, no cluster.
set -uo pipefail
S="${FAKE_STATE:?FAKE_STATE unset}"
args=("$@")
joined="$*"

# Discovery worker Deployment floor 1, siblings floor 1, api floor 2 (matches the
# reduced-scale overlay). Replica state files are created lazily at their floor.
floor_for() {  # $1 = deploy name
  case "$1" in
    *-worker-discovery) echo 1 ;;
    *-worker-config|*-worker-docs|*-worker-packet-*) echo 1 ;;
    *-api) echo 2 ;;
    *) echo 1 ;;
  esac
}
replicas_file() { echo "${S}/rep_$(printf '%s' "$1" | tr '/:' '__')"; }
get_replicas() {  # $1 = deploy name
  local f; f="$(replicas_file "$1")"
  if [ ! -f "$f" ]; then floor_for "$1" > "$f"; fi
  cat "$f"
}
set_replicas() { local f; f="$(replicas_file "$1")"; echo "$2" > "$f"; }

case "${joined}" in
  *"get scaledobject"*"scaleTargetRef.name"*)
    # Resolve the target Deployment name from the SO name (…-worker-<q> -> same).
    so="$(printf '%s\n' "${args[@]}" | grep -E 'worker-' | head -1)"
    echo "${so}"
    exit 0 ;;
  *"get scaledobject"*)
    # precondition existence check for any queue's SO — present.
    exit 0 ;;
  *"get deploy"*"spec.replicas"*)
    dep="$(printf '%s\n' "${args[@]}" | grep -E -- '-(worker-[a-z-]+|api)$' | head -1)"
    # Burst growth: after the discovery RPUSH, discovery grows to its ceiling (2)
    # unless NO_SCALE_OUT=1; after the DEL it returns to floor.
    if printf '%s' "${dep}" | grep -q -- '-worker-discovery$'; then
      if [ -f "${S}/burst_drained" ]; then
        set_replicas "${dep}" "$(floor_for "${dep}")"
      elif [ -f "${S}/burst_pushed" ] && [ "${NO_SCALE_OUT:-0}" != "1" ]; then
        # scale-out to the kind ceiling (2) if still at floor.
        cur="$(get_replicas "${dep}")"
        [ "${cur}" -le "$(floor_for "${dep}")" ] && set_replicas "${dep}" 2
      fi
    fi
    get_replicas "${dep}"
    exit 0 ;;
  *"get secret"*"jsonpath="*)
    # redis / superuser password (base64 of a throwaway dev value — NOT a real secret)
    printf '%s' "ZHJpbGwtZGV2LXB3"; exit 0 ;;   # base64("drill-dev-pw")
  *"get pods"*"redis-sentinel"*|*"get pods"*"redis"*)
    echo "netops-redis-sentinel-0"; exit 0 ;;
  *"scale deploy"*"--replicas="*)
    dep="$(printf '%s\n' "${args[@]}" | grep -E -- '-(worker-[a-z-]+|api)$' | head -1)"
    n="$(printf '%s\n' "${joined}" | sed -n 's/.*--replicas=\([0-9][0-9]*\).*/\1/p')"
    [ -n "${dep}" ] && [ -n "${n}" ] && set_replicas "${dep}" "${n}"
    exit 0 ;;
  *"rollout status"*|*"apply -f"*|*"wait "*|*"delete pod"*)
    exit 0 ;;
  *"exec -i"*)
    # In-pod probe: either redis-cli (burst push / LLEN / DEL) or the bash loadgen.
    # The drill runs redis via `sh -c '… redis-cli -a "$RPW" … -n "$1" $2' _ <db> <cmd>`
    # and the loadgen via `bash -c '…' _ <host> <port> <path> <vus> <reqs> <pool> <neg> …`.
    # Distinguish by scanning the arg vector for the command shape.
    cmd_all="$*"
    if printf '%s' "${cmd_all}" | grep -q 'redis-cli'; then
      # Find the redis command (positional arg after the `_` sentinel: <db> <cmd>).
      rediscmd=""
      for i in "${!args[@]}"; do
        if [ "${args[$i]}" = "_" ]; then rediscmd="${args[$((i+2))]:-}"; break; fi
      done
      case "${rediscmd}" in
        RPUSH\ discovery*) : > "${S}/burst_pushed"; echo "50" ;;
        RPUSH\ *)          echo "5" ;;
        LLEN\ discovery)   if [ -f "${S}/burst_pushed" ] && [ ! -f "${S}/burst_drained" ]; then echo "50"; else echo "0"; fi ;;
        LLEN\ *)           echo "5" ;;
        DEL\ discovery)    : > "${S}/burst_drained"; echo "1" ;;
        DEL\ *)            echo "1" ;;
        *)                 echo "0" ;;
      esac
      exit 0
    fi
    if printf '%s' "${cmd_all}" | grep -q 'EPOCHREALTIME\|one_request\|DRILL queue_burst load'; then
      # The bash loadgen. Read the positional args after the `_` sentinel:
      #   <host> <port> <path> <vus> <reqs> <pool> <neg> <pghost> <pgport> <pgdb> <pguser> <p95budget>
      pool="0"; neg="0"; p95budget="1500"
      for i in "${!args[@]}"; do
        if [ "${args[$i]}" = "_" ]; then
          pool="${args[$((i+6))]:-0}"
          neg="${args[$((i+7))]:-0}"
          p95budget="${args[$((i+12))]:-1500}"
          break
        fi
      done
      # POSITIVE: p95 well under budget, zero 5xx, no exhaustion. The 1-replica call
      # (pool=0) reports a HIGHER p95 than the 2-replica call (pool>0) so the 1->2
      # improvement holds (2 replicas beat 1). NEGATIVE control (only meaningful on
      # the pool>0 call): exhaustion + p95 breach.
      if [ "${pool}" -gt 0 ]; then
        p95=200; err=0; exh=0
        if [ "${neg}" = "1" ]; then
          exh="${pool}"; p95=$(( p95budget + 1000 ))
        fi
      else
        # 1-replica baseline: slower than the 2-replica run above.
        p95=400; err=0; exh=0
      fi
      r=PASS
      { [ "${p95}" -le "${p95budget}" ] && [ "${err}" -eq 0 ] && [ "${exh}" -eq 0 ]; } || r=FAIL
      echo "DRILL queue_burst load p95_ms=${p95} errors_5xx=${err} exhaustion=${exh} result=${r}"
      exit 0
    fi
    # Any other exec → succeed quietly.
    exit 0 ;;
  *)
    exit 0 ;;
esac
FAKE
chmod +x "${FAKE_BIN}/kubectl"

# --- scenario runner -----------------------------------------------------------
# Runs the REAL check with the fake kubectl first on PATH and fast poll windows.
# Extra env shapes the scenario. Returns the check's exit; captures its log.
run_scenario() {
  local state; state="$(mktemp -d)"
  local log="${WORK}/scenario.log"
  (
    export PATH="${FAKE_BIN}:${PATH}"
    export FAKE_STATE="${state}"
    export CHART_NS="netops"
    # keep the drill fast + deterministic (tiny windows / load).
    export QUEUE_BURST_SCALE_OUT_POLL_S="15"
    export QUEUE_BURST_SCALE_IN_POLL_S="15"
    export API_LOAD_VUS="2"
    export API_LOAD_REQUESTS="4"
    export POOL_PROBE_CONNS="4"
    "$@"
    bash "${CHECK}"
  ) >"${log}" 2>&1
  local rc=$?
  LAST_LOG="${log}"
  return "${rc}"
}

# --- 1. POSITIVE — scale-out/in, no starvation, p95 held, no exhaustion → GREEN --
run_scenario true
rc_pos=$?
if [ "${rc_pos}" -eq 0 ]; then
  ok "POSITIVE path: 10x discovery burst → scale-out then scale-in, siblings not starved, p95 held + 1->2 improvement + zero 5xx, PgBouncer no exhaustion → drill GREEN (exit 0)"
else
  bad "POSITIVE path FALSE-RED: the happy-path drill exited ${rc_pos} (should be 0) — check ${LAST_LOG}"
  sed 's/^/    | /' "${LAST_LOG}" >&2 || true
fi

# --- 2. NEGATIVE CONTROL — sibling starvation + connection-budget breach → RED ---
run_scenario export QUEUE_BURST_DRILL_NEGATIVE_CONTROL=1
rc_neg=$?
if [ "${rc_neg}" -ne 0 ]; then
  ok "NEGATIVE CONTROL: shared scaler starves a sibling + PgBouncer budget overrun → drill RED (exit ${rc_neg}) — the per-queue-isolation / §330 / §327 assertions BITE (ADR-0047 §2)"
else
  bad "FALSE-GREEN: the negative control did NOT turn the drill red (exit 0) — the drill does not bite; it is not a gate (ADR-0047 §2)"
fi
# The bite must be the ISOLATION and/or connection-budget assertion specifically.
if grep -q "was STARVED\|per-queue isolation VIOLATED\|connection-exhaustion error\|G-SCA §330 .* VIOLATED\|EXCEEDS the .* budget" "${LAST_LOG}"; then
  ok "negative-control RED is the isolation / connection-budget assertion (not an incidental failure)"
else
  bad "negative-control turned red but NOT via the isolation/budget assertion — check the bite is attributable (${LAST_LOG})"
fi

# --- 3. NO-SCALE-OUT — burst never moves the replica count → RED -----------------
# A "burst" that does not move the replica count is the exact spec false-green risk.
run_scenario export NO_SCALE_OUT=1
rc_nso=$?
if [ "${rc_nso}" -ne 0 ]; then
  ok "NO-SCALE-OUT path: the discovery replica count never grew under the burst → drill RED (exit ${rc_nso}) — the 'replica count actually changed' assertion bites (G-SCA §329)"
else
  bad "FALSE-GREEN: the burst never scaled out yet the drill passed (exit 0) — the scale-out assertion does not bite (the spec's false-green risk)"
fi
if grep -q "did NOT scale out\|no scale-out\|G-SCA §329 VIOLATED" "${LAST_LOG}"; then
  ok "no-scale-out RED is the scale-out assertion specifically (attributable bite)"
else
  bad "no-scale-out turned red but NOT via the scale-out assertion — check the bite is attributable (${LAST_LOG})"
fi

echo "== queue-burst-load-bite summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::queue-burst/load bite proof found ${fails} violation(s)" >&2
  exit 1
fi
echo "queue-burst/load bite proof: the drill is GREEN on scale-out/in + isolation + p95/1->2 + no-exhaustion and RED on sibling starvation / connection-budget breach / no-scale-out (ADR-0047 §2 negative control bites; ADR-0043 §3 per-queue isolation; ADR-0042 §4 connection budget)."
