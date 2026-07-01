#!/usr/bin/env bash
# W4-T4 Neo4j destroy-and-rebuild drill (G-REL §317; ADR-0005 D5/§3, ADR-0030 §1,
# ADR-0047 §1/§2/§3/§4/§5) — plugged into the W4-T1 HA kind assertion-runner.
#
# §11 G-REL §317 CRITERION (stated in the header per ADR-0047 §1):
#   DESTROY Neo4j → the FULL topology is RE-PROJECTED FROM POSTGRES (the system of
#   record, ADR-0005 D5 — NOT restored from a Neo4j dump) within the measured
#   topology-RTO, and the restored node/edge counts MATCH the Postgres source of
#   record (a PARTIAL rebuild fails). The rebuild wall-clock at this run's scale
#   BECOMES the topology-RTO (ADR-0047 §3: measured, not asserted against a fixed
#   number; the < 30 min @ 5,000-device certified ceiling is NAMED-deferred → GA).
#
# WHY REBUILD-FROM-POSTGRES, NOT A DUMP (ADR-0005 D5): Neo4j Community has no
# clustering and holds NO un-rebuildable state — it is a PURE projection of
# Postgres. So DR is a full RE-PROJECTION from the relational source of truth, and
# a restored stale graph dump could DISAGREE with authoritative Postgres (forbidden
# by D5). This drill destroys the graph (pod + data PVC) and drives the EXISTING
# W1-T3 auto-rebuild reconciler (python -m app.engines.topology.auto_rebuild →
# metrics.timed_rebuild → rebuild() → projector.full_rebuild), which re-derives the
# whole topology from the normalized_* tables — never from a graph backup.
#
# THE BITE (drill-as-test + negative control, ADR-0047 §2 — the single most
# important rule): the drill SHIPS a planted regression that turns the completeness
# assertion RED. With NEO4J_REBUILD_DRILL_NEGATIVE_CONTROL=1 the rebuild is
# DISABLED (the auto-rebuild reconcile step is skipped) — exactly the ADR-0047 §2
# Neo4j-rebuild control ("a broken/disabled rebuild Job … → topology not restored
# in budget"). The graph is destroyed and NOT re-projected, so the live Neo4j
# node/edge counts (0) do NOT match the Postgres source of record → the
# completeness assertion goes RED regardless of timing. A drill that only ever runs
# the happy path — or whose "rebuild" reads a Neo4j dump — is not a gate (P1-W4
# false-green; ADR-0005 D5). See docs/runbooks/kind-harness.md "Neo4j rebuild drill".
#
# REDUCED SCALE (ADR-0047 §1/§4 — NAMED, never claimed as certified): this runs on
# the W4-T1 reduced-scale kind cluster with a small FIXED seeded inventory (2
# devices, addressed interfaces, one L2 link, a route, a VRF → a handful of
# projected nodes/edges). It proves the destroy → rebuild-from-Postgres →
# completeness MECHANISM bites and MEASURES the reduced-scale rebuild time (which
# becomes the topology-RTO for this run). It does NOT certify a scale point: the
# 5,000-device / <30-min topology-RTO ceiling (G-REL §317) stays deferred-accepted
# → GA with the ADR-0047 §4 written promotion path (a 5,000-device dataset; re-run
# this drill; assert measured RTO < 30 min) — never claimed from this run.
#
# REAL PG + REAL NEO4J ONLY (ADR-0047 §5): the rebuild-from-relational-source
# semantics are meaningless on SQLite (no graph projection). The counts helper
# (topology_counts.py) HARD-FAILS if database_url is not a postgresql URL. There is
# no SQLite path.
#
# L1: kind CANNOT run on the Windows authoring host (no Docker/Linux kind), so this
# drill is authored + STATICALLY validated here (ci/kind/selftest/validate-harness.sh)
# and PROVEN to bite hardware-free (ci/kind/selftest/neo4j-rebuild-bite.sh); it runs
# LIVE only on the CI ubuntu runner via the `kind-harness-ha` job. That job stays
# continue-on-error / ABSENT from `all-gates` — promoting the G-REL drill to blocking
# is a deliberate later step (W5/GA), not W4-T4.
# L3: every value the in-pod python needs (the assembled Postgres DSN, the Neo4j
#     password split from NETOPS_NEO4J_AUTH, the base64 script, the subcommand) is a
#     POSITIONAL arg to `sh -c` ("$1" …), never $(VAR) in the exec argv.
# L5: pipefail is on (the runner sets it globally); each captured in-pod output is
#     guarded (test -n / parsed) so a masked exit / empty read can never read green.
#
# SECRET SURFACE (topology projection touches the audit-adjacent DB + Neo4j creds,
# escalated per the agents README): the Postgres + Neo4j passwords are read INSIDE
# the pod from its own env (secretKeyRef, never printed), assembled into the DSN in
# the in-pod shell, and NEVER echoed, argv-passed, or written to a drill log. The
# base64 payload passed via argv is the count HELPER SOURCE only — it carries no
# secret.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
. "${HERE}/../lib.sh"

NS="${CHART_NS:-netops}"

# Chart object names (reduced-scale HA overlay, values-kind-ha.yaml).
NEO4J_STS="${NEO4J_STS:-netops-neo4j}"
NEO4J_POD="${NEO4J_POD:-netops-neo4j-0}"
NEO4J_PVC="${NEO4J_PVC:-data-netops-neo4j-0}"
# The reconcile CronJob the W1-T3 auto-rebuild ships (we create an on-demand Job
# from it to force + time a re-projection). Its post-rollout Job shares the name.
REBUILD_CRONJOB="${REBUILD_CRONJOB:-netops-neo4j-auto-rebuild}"

# The count HELPER runs on a chart WORKER pod (backend image: has app.engines.topology
# + the neo4j driver + asyncpg, and the config/secret env to reach PG + Neo4j). We
# select a Ready worker rather than shipping a new probe image (the backend image is
# built locally, not a digest-pinnable public ref).
WORKER_SELECTOR="${WORKER_SELECTOR:-app.kubernetes.io/component=worker}"

# Reduced-scale knobs (STATED, ADR-0047 §1). The topology-RTO is MEASURED here;
# RTO_BUDGET_S bounds the reduced-scale rebuild so a MISS is caught (RTO > budget →
# FAIL), not a hang. It is NOT the certified < 30-min ceiling (that is deferred, §4).
RTO_BUDGET_S="${NEO4J_REBUILD_RTO_BUDGET_S:-300}"
# How long to poll for the graph to be re-projected complete after the rebuild
# fires. Bounded ABOVE the RTO budget so an over-budget rebuild is MEASURED, not a
# hang; a genuinely disabled rebuild (negative control) still terminates.
REBUILD_POLL_S="${NEO4J_REBUILD_POLL_S:-360}"

# NEGATIVE CONTROL (ADR-0047 §2): when =1, the rebuild is DISABLED (the reconcile
# step is skipped) so the destroyed graph is NOT re-projected → counts mismatch → RED.
NEG_CONTROL="${NEO4J_REBUILD_DRILL_NEGATIVE_CONTROL:-0}"

COUNTS_SCRIPT="${HERE}/topology_counts.py"

echo "== W4-T4 Neo4j destroy-and-rebuild drill (G-REL §317; ns=${NS}, sts=${NEO4J_STS}) =="
echo "   reduced scale: fixed seeded inventory (2 devices + interfaces/link/route/VRF);" \
     "RTO budget=${RTO_BUDGET_S}s (topology-RTO is MEASURED); negative_control=${NEG_CONTROL}"
echo "   certified-scale topology-RTO (< 30 min @ 5,000 devices, G-REL §317) is NAMED" \
     "deferred-accepted -> GA (ADR-0047 §4) — NOT claimed here."

# --- precondition: a Neo4j StatefulSet must be present, else SKIP LOUDLY --------
# On a NON-HA / no-Neo4j harness run there is no graph to destroy/rebuild. Assert
# nothing rather than read a missing store as a pass (a silent no-op is a
# false-green; the runner also fails an empty log, so we always emit).
if ! kubectl -n "${NS}" get statefulset "${NEO4J_STS}" >/dev/null 2>&1; then
  echo "SKIP: Neo4j StatefulSet '${NEO4J_STS}' absent in ns '${NS}' — this is a run"
  echo "      without the Neo4j projection tier. The rebuild drill asserts only when"
  echo "      Neo4j is deployed. Nothing to drill on this run (loud SKIP, never a"
  echo "      false-green pass)."
  exit 0
fi
if [ ! -f "${COUNTS_SCRIPT}" ]; then
  _fail "topology_counts.py helper missing at ${COUNTS_SCRIPT} — the drill cannot count"
  echo "== drill aborted: helper missing =="
  exit "$(assert_failures)"
fi

# --- pick a Ready worker pod to run the counts helper on -----------------------
WORKER_POD="$(kubectl -n "${NS}" get pods -l "${WORKER_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "${WORKER_POD}" ]; then
  _fail "no Running worker pod (${WORKER_SELECTOR}) in ns ${NS} — cannot run the counts helper (backend image)"
  echo "== drill aborted: no worker pod =="
  exit "$(assert_failures)"
fi
echo "counts helper runs on worker pod: ${WORKER_POD}"

# base64 the (secret-free) helper source ONCE; passed as a positional arg to the
# in-pod sh -c (L3), decoded to /tmp (RO rootfs; /tmp is the writable scratch), and
# run by PATH so app.* resolves from the backend image without a PYTHONPATH change.
COUNTS_B64="$(base64 "${COUNTS_SCRIPT}" | tr -d '\n')"

# --- in-pod helper runner ------------------------------------------------------
# Runs `python /tmp/topology_counts.py <sub>` inside the worker pod. The DSN + Neo4j
# password are assembled IN-POD from the pod's own secretKeyRef env (never printed /
# never argv), mirroring the W1-T3 auto-rebuild Job's DSN assembly exactly (L3: all
# $VARs expand inside ONE sh -c; percent-encode user/pass; split NEO4J_AUTH). Echoes
# the helper's single `DRILL neo4j_rebuild <sub> nodes=<n> edges=<n> result=…` line.
run_counts() {
  local sub="$1"
  kubectl -n "${NS}" exec "${WORKER_POD}" -- sh -c '
    set -eu
    SUB="$1"
    B64="$2"
    printf "%s" "$B64" | base64 -d > /tmp/topology_counts.py
    # Assemble NETOPS_DATABASE_URL from the config-map coords + the secret password
    # (the worker env carries NETOPS_POSTGRES_* + the password secretKeyRef, but not
    # a ready DSN). Percent-encode user + password so a : / @ / % in either cannot
    # corrupt the authority. python is present on the backend image.
    NETOPS_PG_USER_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_USER\"],safe=\"\"))")"
    NETOPS_PG_PASS_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_PASSWORD\"],safe=\"\"))")"
    export NETOPS_DATABASE_URL="postgresql+asyncpg://${NETOPS_PG_USER_ENC}:${NETOPS_PG_PASS_ENC}@${NETOPS_POSTGRES_HOST}:${NETOPS_POSTGRES_PORT}/${NETOPS_POSTGRES_DB}"
    # The Neo4j Secret stores user/password as one NETOPS_NEO4J_AUTH value
    # (the neo4j-image NEO4J_AUTH shape); the client reads NETOPS_NEO4J_PASSWORD, so
    # split the password out in-shell (never a manifest/argv value).
    export NETOPS_NEO4J_PASSWORD="${NETOPS_NEO4J_AUTH#*/}"
    exec python /tmp/topology_counts.py "$SUB"
  ' _ "${sub}" "${COUNTS_B64}"
}

# Parse `nodes=<n>` / `edges=<n>` out of a helper line into shell vars.
parse_count() {  # $1 = full helper output, $2 = field (nodes|edges)
  printf '%s\n' "$1" | sed -n "s/.* $2=\([0-9][0-9]*\).*/\1/p" | head -1
}

cleanup() {
  # Best-effort: purge the drill-owned inventory rows (idempotent) + drop the
  # on-demand rebuild Job we created. Never fatal.
  run_counts purge >/dev/null 2>&1 || true
  kubectl -n "${NS}" delete job "${REBUILD_CRONJOB}-drill" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
# N1: compose teardown with lib.sh's assert-exit trap (a bare `trap cleanup EXIT`
# would CLOBBER the assert-fail bite → false-green).
register_cleanup cleanup

# --- 1. SEED a fixed reduced-scale topology into Postgres (the SOURCE) ----------
echo "seeding the fixed reduced-scale inventory into Postgres (the source of record, D5)"
SEED_OUT="$(run_counts seed || true)"
echo "${SEED_OUT}"
PG_NODES="$(parse_count "${SEED_OUT}" nodes)"
PG_EDGES="$(parse_count "${SEED_OUT}" edges)"
if [ -z "${PG_NODES}" ] || [ -z "${PG_EDGES}" ] || [ "${PG_NODES}" -le 0 ] || [ "${PG_EDGES}" -le 0 ]; then
  _fail "seed produced no source topology (nodes='${PG_NODES}' edges='${PG_EDGES}') — cannot trust the drill baseline"
  echo "== drill aborted: seed failed =="
  exit "$(assert_failures)"
fi

# --- 2. record the Postgres SOURCE-OF-RECORD counts (what a complete rebuild owes)
# Recomputed from Postgres ALONE (derive_topology → snapshot_lists). This is the
# obligation a faithful re-projection must meet (D5). Neo4j is not touched.
SOURCE_OUT="$(run_counts pg-source || true)"
echo "${SOURCE_OUT}"
SRC_NODES="$(parse_count "${SOURCE_OUT}" nodes)"
SRC_EDGES="$(parse_count "${SOURCE_OUT}" edges)"
if [ -z "${SRC_NODES}" ] || [ -z "${SRC_EDGES}" ] || [ "${SRC_NODES}" -le 0 ]; then
  _fail "could not read the Postgres source-of-record counts — cannot assert completeness"
  echo "== drill aborted: source count failed =="
  exit "$(assert_failures)"
fi
echo "Postgres source of record: nodes=${SRC_NODES} edges=${SRC_EDGES} (a complete rebuild MUST match these)"

# --- 2a. PROJECT once so the graph exists BEFORE we destroy it ------------------
# Force an initial projection so there is a real graph to destroy (the reconcile
# re-projects an empty/stale graph; on the first run the graph may already be empty
# of OUR rows). staleness=0 forces an unconditional rebuild.
echo "priming the projection (initial re-project so the graph holds the seeded topology)"
run_initial_reconcile() {
  kubectl -n "${NS}" exec "${WORKER_POD}" -- sh -c '
    set -eu
    NETOPS_PG_USER_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_USER\"],safe=\"\"))")"
    NETOPS_PG_PASS_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_PASSWORD\"],safe=\"\"))")"
    export NETOPS_DATABASE_URL="postgresql+asyncpg://${NETOPS_PG_USER_ENC}:${NETOPS_PG_PASS_ENC}@${NETOPS_POSTGRES_HOST}:${NETOPS_POSTGRES_PORT}/${NETOPS_POSTGRES_DB}"
    export NETOPS_NEO4J_PASSWORD="${NETOPS_NEO4J_AUTH#*/}"
    exec python -m app.engines.topology.auto_rebuild \
      --metrics-textfile /tmp/topology_rebuild_seconds.prom \
      --staleness-seconds 0
  ' _
}
run_initial_reconcile || true

# --- 3. DESTROY Neo4j — graph loss (pod + data PVC), the failure this drill models
# Delete the data PVC AND force-delete the pod so the StatefulSet recreates it with
# an EMPTY volume — a total projection loss (the ADR-0005 D5 recovery scenario). We
# time the rebuild FROM the destroy.
echo "DESTROYING Neo4j (delete data PVC + force-delete pod → StatefulSet recreates EMPTY)"
DESTROY_EPOCH="$(date +%s)"
kubectl -n "${NS}" delete pvc "${NEO4J_PVC}" --ignore-not-found --wait=false || true
kubectl -n "${NS}" delete pod "${NEO4J_POD}" --force --grace-period=0 --wait=false || true
# Wait for the StatefulSet to bring the pod back Ready (empty graph) before rebuild.
echo "waiting for Neo4j to be recreated + Ready (empty graph) before the rebuild"
kubectl -n "${NS}" rollout status "statefulset/${NEO4J_STS}" --timeout=240s || true
kubectl -n "${NS}" wait --for=condition=Ready "pod/${NEO4J_POD}" --timeout=240s || true

# --- 4. REBUILD FROM POSTGRES (the W1-T3 auto-rebuild path), MEASURE the RTO -----
# On the POSITIVE path we drive the reconcile (re-project the WHOLE Postgres
# inventory into the fresh, empty Neo4j). On the NEGATIVE CONTROL we SKIP the
# reconcile (a disabled rebuild Job, ADR-0047 §2) so the graph stays empty and the
# completeness assertion goes RED. Either way we POLL until the graph matches the
# source (positive) or the poll window elapses (negative → RTO not met → RED).
if [ "${NEG_CONTROL}" = "1" ]; then
  echo "::warning::NEGATIVE CONTROL active — the rebuild is DISABLED (reconcile skipped)." \
       "The destroyed graph is NOT re-projected from Postgres; the completeness assertion" \
       "is EXPECTED to go RED (proving the drill bites; ADR-0047 §2 / ADR-0005 D5)."
else
  echo "REBUILDING from Postgres (W1-T3 auto-rebuild reconcile; re-project the whole inventory)"
  run_initial_reconcile || true
fi

echo "polling the live Neo4j graph for a COMPLETE re-projection (counts == Postgres source)..."
REBUILT=0
RTO_S=""
NEO_NODES=""
NEO_EDGES=""
poll_deadline=$(( DESTROY_EPOCH + REBUILD_POLL_S ))
while [ "$(date +%s)" -lt "${poll_deadline}" ]; do
  GRAPH_OUT="$(run_counts neo4j-graph 2>/dev/null || true)"
  NEO_NODES="$(parse_count "${GRAPH_OUT}" nodes)"
  NEO_EDGES="$(parse_count "${GRAPH_OUT}" edges)"
  if [ -n "${NEO_NODES}" ] && [ -n "${NEO_EDGES}" ] && \
     [ "${NEO_NODES}" = "${SRC_NODES}" ] && [ "${NEO_EDGES}" = "${SRC_EDGES}" ]; then
    RTO_S=$(( $(date +%s) - DESTROY_EPOCH ))
    REBUILT=1
    echo "graph fully re-projected: nodes=${NEO_NODES} edges=${NEO_EDGES} at RTO=${RTO_S}s (from destroy)"
    break
  fi
  sleep 3
done
# On the negative control (or a genuine failure) capture the final observed counts.
if [ "${REBUILT}" -ne 1 ]; then
  GRAPH_OUT="$(run_counts neo4j-graph 2>/dev/null || true)"
  NEO_NODES="$(parse_count "${GRAPH_OUT}" nodes)"
  NEO_EDGES="$(parse_count "${GRAPH_OUT}" edges)"
fi
NEO_NODES="${NEO_NODES:-0}"
NEO_EDGES="${NEO_EDGES:-0}"

# --- 5. ASSERT: full topology re-projected FROM POSTGRES within the topology-RTO -
# (a) COMPLETENESS — rebuilt node/edge counts MATCH the Postgres source (a partial
#     rebuild — the negative control's disabled/broken reconcile — reads FEWER).
if [ "${NEO_NODES}" = "${SRC_NODES}" ] && [ "${NEO_EDGES}" = "${SRC_EDGES}" ]; then
  _pass "rebuilt topology MATCHES the Postgres source of record (nodes=${NEO_NODES}=${SRC_NODES}, edges=${NEO_EDGES}=${SRC_EDGES}) — full re-projection from Postgres, D5"
else
  _fail "rebuilt topology does NOT match the Postgres source of record: Neo4j nodes=${NEO_NODES} edges=${NEO_EDGES} vs source nodes=${SRC_NODES} edges=${SRC_EDGES} — topology NOT fully restored from Postgres (G-REL §317 VIOLATED; a partial/disabled rebuild — ADR-0005 D5 / ADR-0047 §2)"
fi
# (b) WITHIN topology-RTO — the rebuild wall-clock is <= the (reduced-scale) budget.
#     The measured RTO_S BECOMES the topology-RTO for this scale (ADR-0047 §3). A
#     never-completing rebuild (negative control) has no RTO → RED.
if [ "${REBUILT}" -eq 1 ] && [ "${RTO_S}" -le "${RTO_BUDGET_S}" ]; then
  _pass "topology re-projected in ${RTO_S}s <= ${RTO_BUDGET_S}s (the MEASURED reduced-scale topology-RTO; G-REL §317)"
elif [ "${REBUILT}" -eq 1 ]; then
  _fail "topology re-projected but RTO=${RTO_S}s EXCEEDS the ${RTO_BUDGET_S}s reduced-scale budget (G-REL §317)"
else
  _fail "topology NOT fully re-projected within ${REBUILD_POLL_S}s of the destroy — no complete rebuild observed (G-REL §317; disabled/broken rebuild — ADR-0047 §2)"
fi

# Emit the composite W5-T5 collector line (mirrors the P1 seeded-dry-run harness).
_measured_rto="${RTO_S:-NA}"
echo "DRILL neo4j_rebuild seconds=${_measured_rto} nodes=${NEO_NODES} edges=${NEO_EDGES} result=$([ "$(assert_failures)" = "0" ] && echo PASS || echo FAIL)"

echo "== W4-T4 Neo4j rebuild drill complete: $(assert_failures) failure(s) =="
echo "   scale: fixed seeded inventory (source nodes=${SRC_NODES} edges=${SRC_EDGES});" \
     "MEASURED reduced-scale topology-RTO=${_measured_rto}s (budget ${RTO_BUDGET_S}s)."
echo "   certified-scale topology-RTO (< 30 min @ 5,000 devices, G-REL §317):" \
     "NAMED deferred-accepted -> GA (ADR-0047 §4 promotion path)."
