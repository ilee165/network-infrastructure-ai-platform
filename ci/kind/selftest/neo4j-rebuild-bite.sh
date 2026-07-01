#!/usr/bin/env bash
# EMPIRICAL, HARDWARE-FREE bite proof for the W4-T4 Neo4j destroy-and-rebuild drill
# (ADR-0047 §2 — the negative-control rule; ADR-0005 D5 rebuild-from-Postgres).
#
# WHY THIS EXISTS (L1 + ADR-0047 §2): the rebuild drill (neo4j-rebuild.sh) runs LIVE
# only on a kind cluster, which CANNOT run on the authoring host (Windows, no
# Docker/Linux kind). ADR-0047 §2 nonetheless requires every drill's negative
# control be SHOWN to bite (plant → red → revert), never merely asserted. This
# self-test earns that proof WITHOUT a cluster: it runs the REAL neo4j-rebuild.sh
# check against a FAKE `kubectl` that simulates the Neo4j StatefulSet + a worker pod
# running the counts helper + the auto-rebuild reconcile, and asserts the OBSERVABLE
# polarity:
#   POSITIVE  — destroy → reconcile re-projects the whole topology from Postgres →
#               live Neo4j counts MATCH the Postgres source → drill GREEN (exit 0)
#   NEGATIVE  — rebuild DISABLED (NEO4J_REBUILD_DRILL_NEGATIVE_CONTROL=1) → the
#               destroyed graph is never re-projected → live counts (0) do NOT match
#               the source → completeness assertion RED → drill RED (exit != 0)
#   PARTIAL   — the reconcile projects only SOME of the topology (a projection-source
#               gap) → counts < source → RED (the ADR-0047 §2 "projection gap" case)
#
# The NEGATIVE / PARTIAL scenarios are the planted regressions; POSITIVE is the
# revert-to-green. This is the executed plant→red→revert the live kind run would
# otherwise be the only place to observe (recorded here as a runnable proof; the
# live CI run corroborates it on the reduced-scale cluster).
#
# The fake kubectl interprets exactly the calls neo4j-rebuild.sh makes (get
# statefulset, get pods -l worker, exec … topology_counts.py <sub>, exec …
# auto_rebuild, delete pvc/pod, rollout status, wait). It serves canned counts from
# a state dir it mutates: the graph is EMPTY until an auto_rebuild exec is seen
# (models "rebuild from Postgres re-projects it"), so SKIPPING the reconcile (the
# negative control) leaves the graph empty → the completeness bite fires.
#
# Run: ci/kind/selftest/neo4j-rebuild-bite.sh   (exits non-zero on any violation)
# CI:  the `kind-harness-ha` job runs this (no cluster needed — it is the local
#      bite proof for the live drill's negative control).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"
CHECK="${KIND_DIR}/assertions/checks/neo4j-rebuild.sh"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

if [ ! -f "${CHECK}" ]; then
  echo "::error::neo4j-rebuild.sh not found at ${CHECK}" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- the FAKE kubectl ----------------------------------------------------------
# A stand-in `kubectl` on PATH simulating just enough of the Neo4j StatefulSet + a
# worker pod running topology_counts.py + the auto_rebuild reconcile. State lives in
# $FAKE_STATE: the seeded source counts + a "rebuilt" flag set when an auto_rebuild
# exec is seen. SRC_NODES/SRC_EDGES define the source of record; PARTIAL_NODES lets
# a scenario model a projection-source gap (rebuild projects fewer than the source).
FAKE_BIN="${WORK}/bin"
mkdir -p "${FAKE_BIN}"
cat > "${FAKE_BIN}/kubectl" <<'FAKE'
#!/usr/bin/env bash
# Fake kubectl for the neo4j-rebuild drill self-test. Deterministic, no cluster.
set -uo pipefail
S="${FAKE_STATE:?FAKE_STATE unset}"
joined="$*"
SRC_NODES="${SRC_NODES:-9}"
SRC_EDGES="${SRC_EDGES:-7}"

# Emit a topology_counts-style line the drill parses.
emit() { echo "DRILL neo4j_rebuild $1 nodes=$2 edges=$3 result=$4"; }

# Live graph counts: EMPTY until a rebuild (auto_rebuild exec) has run. After a
# rebuild the graph holds the (possibly PARTIAL) projected counts. A destroy resets
# the rebuilt flag (graph lost) so a subsequent skipped reconcile stays empty.
graph_counts() {
  if [ -f "${S}/rebuilt" ]; then
    if [ "${PARTIAL:-0}" = "1" ]; then
      echo "${PARTIAL_NODES:-4} ${PARTIAL_EDGES:-3}"      # projection-source gap
    else
      echo "${SRC_NODES} ${SRC_EDGES}"                    # full re-projection
    fi
  else
    echo "0 0"                                            # destroyed / never rebuilt
  fi
}

case "${joined}" in
  *"get statefulset"*)
    exit 0 ;;                                             # Neo4j STS present
  *"get pods"*"component=worker"*|*"get pods -l"*"worker"*)
    echo "netops-worker-drillfake"; exit 0 ;;            # a Running worker pod
  *"delete pvc"*)
    exit 0 ;;
  *"delete pod"*"--force"*)
    : > "${S}/destroyed"; rm -f "${S}/rebuilt"           # graph lost on destroy
    exit 0 ;;
  *"delete pod"*|*"delete job"*)
    exit 0 ;;
  *"rollout status"*|*"wait "*)
    exit 0 ;;                                             # STS recreated + Ready
  *"exec"*)
    # In-pod work. The drill runs two exec shapes inside `sh -c`:
    #   (1) python /tmp/topology_counts.py <sub>   (seed | pg-source | neo4j-graph | purge)
    #   (2) python -m app.engines.topology.auto_rebuild …  (the reconcile / rebuild)
    if printf '%s' "${joined}" | grep -q 'auto_rebuild'; then
      # The rebuild reconcile ran → re-project the graph from Postgres.
      : > "${S}/rebuilt"
      echo "REBUILD neo4j_auto rebuilt=true seconds=1.000 nodes=${SRC_NODES} edges=${SRC_EDGES} result=PASS"
      exit 0
    fi
    case "${joined}" in
      *"topology_counts.py seed"*|*" seed"*)
        : > "${S}/seeded"; emit seed "${SRC_NODES}" "${SRC_EDGES}" PASS; exit 0 ;;
      *"topology_counts.py pg-source"*|*" pg-source"*)
        emit pg-source "${SRC_NODES}" "${SRC_EDGES}" PASS; exit 0 ;;
      *"topology_counts.py neo4j-graph"*|*" neo4j-graph"*)
        read -r gn ge < <(graph_counts); emit neo4j-graph "${gn}" "${ge}" PASS; exit 0 ;;
      *"topology_counts.py purge"*|*" purge"*)
        emit purge 0 0 PASS; exit 0 ;;
      *)
        exit 0 ;;                                         # any other in-pod cmd
    esac
    ;;
  *)
    exit 0 ;;
esac
FAKE
chmod +x "${FAKE_BIN}/kubectl"

# --- scenario runner -----------------------------------------------------------
# Runs the REAL check with the fake kubectl first on PATH and a fast poll budget.
# The check reads topology_counts.py from its OWN dir; the fake never runs it (it
# answers the counts calls directly), so no app package is needed. Extra env shapes
# the scenario (negative control flag / PARTIAL gap). Returns the check's exit.
run_scenario() {
  local state; state="$(mktemp -d)"
  local log="${WORK}/scenario.log"
  (
    export PATH="${FAKE_BIN}:${PATH}"
    export FAKE_STATE="${state}"
    export CHART_NS="netops"
    # keep the drill fast + deterministic (short poll; small RTO budget).
    export NEO4J_REBUILD_RTO_BUDGET_S="60"
    export NEO4J_REBUILD_POLL_S="8"
    "$@"
    bash "${CHECK}"
  ) >"${log}" 2>&1
  local rc=$?
  LAST_LOG="${log}"
  return "${rc}"
}

# --- 1. POSITIVE — destroy → reconcile re-projects → counts match → GREEN -------
run_scenario true
rc_pos=$?
if [ "${rc_pos}" -eq 0 ]; then
  ok "POSITIVE path: destroy → rebuild-from-Postgres → counts match source → drill GREEN (exit 0)"
else
  bad "POSITIVE path FALSE-RED: the happy-path drill exited ${rc_pos} (should be 0) — check ${LAST_LOG}"
  sed 's/^/    | /' "${LAST_LOG}" >&2 || true
fi

# --- 2. NEGATIVE CONTROL — rebuild DISABLED → graph empty → RED (the bite) ------
run_scenario export NEO4J_REBUILD_DRILL_NEGATIVE_CONTROL=1
rc_neg=$?
if [ "${rc_neg}" -ne 0 ]; then
  ok "NEGATIVE CONTROL: rebuild disabled → destroyed graph never re-projected → drill RED (exit ${rc_neg}) — the completeness/topology-restored assertion BITES (ADR-0047 §2 / ADR-0005 D5)"
else
  bad "FALSE-GREEN: the negative control (disabled rebuild) did NOT turn the drill red (exit 0) — the drill does not bite; it is not a gate (ADR-0047 §2)"
fi
# The bite must be the completeness / RTO assertion specifically (not an unrelated error).
if grep -q "does NOT match the Postgres source\|NOT fully restored from Postgres\|NOT fully re-projected\|topology NOT" "${LAST_LOG}"; then
  ok "negative-control RED is the rebuild-from-Postgres completeness/RTO assertion (not an incidental failure)"
else
  bad "negative-control turned red but NOT via the completeness/RTO assertion — check the bite is attributable (${LAST_LOG})"
fi

# --- 3. PARTIAL — projection-source gap → counts < source → RED ----------------
# The rebuild runs but projects FEWER nodes/edges than Postgres holds (the ADR-0047
# §2 "projection-source gap" case). The completeness assertion must still bite.
run_scenario export PARTIAL=1
rc_partial=$?
if [ "${rc_partial}" -ne 0 ]; then
  ok "PARTIAL path: a projection-source gap (rebuilt counts < source) → drill RED (exit ${rc_partial}) — the completeness assertion bites on an incomplete rebuild"
else
  bad "FALSE-GREEN: a partial rebuild (fewer nodes/edges than Postgres) passed (exit 0) — the completeness assertion does not bite"
fi

echo "== neo4j-rebuild-bite summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::neo4j-rebuild bite proof found ${fails} violation(s)" >&2
  exit 1
fi
echo "neo4j-rebuild bite proof: the drill is GREEN on full rebuild-from-Postgres and RED on disabled-rebuild / partial-projection (ADR-0047 §2 negative control bites; ADR-0005 D5)."
