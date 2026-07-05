#!/usr/bin/env bash
# EMPIRICAL, HARDWARE-FREE bite proof for the W4-T8 N-2 -> N upgrade rehearsal drill
# (ADR-0047 §2 — the negative-control rule; G-MNT §346; PRODUCTION.md §10 expand/
# contract; ADR-0038 audit hash-chain).
#
# WHY THIS EXISTS (L1 + ADR-0047 §2): the upgrade rehearsal (n2-upgrade-rehearsal.sh)
# runs LIVE only on a kind cluster with the CNPG HA tier + api + workers, which CANNOT
# run on the authoring host (Windows, no Docker/Linux kind). ADR-0047 §2 nonetheless
# requires every drill's negative control be SHOWN to bite (plant -> red -> revert),
# never merely asserted. This self-test earns that proof WITHOUT a cluster: it runs the
# REAL n2-upgrade-rehearsal.sh against a FAKE `kubectl` that simulates the CNPG
# Cluster, a worker pod running alembic, the psql probe pod, and the api rolling
# restart, and asserts the OBSERVABLE polarity:
#   POSITIVE  — additive EXPAND migration + rolling order + rebuild -> the N-1 reader
#               still works, no data loss, audit intact, api held >=2 ready -> GREEN
#   NEGATIVE  — CONTRACT-TOO-EARLY (N2_UPGRADE_DRILL_NEGATIVE_CONTROL=1): the migration
#               DROPS the column an N-1 pod still reads -> the N-1 reader breaks ->
#               "rolling upgrade without downtime" VIOLATED -> RED
#   AVAIL     — FORCE-API-UNAVAIL (N2_UPGRADE_DRILL_FORCE_API_UNAVAIL=1): the api is
#               driven below its >=2-ready floor during the roll -> the no-downtime
#               assertion goes RED
#
# The NEGATIVE / AVAIL scenarios are the planted regressions; POSITIVE is the
# revert-to-green. A rehearsal whose "no downtime / no data loss" would read green
# whether or not the N-1 reader survived — or whether or not the api stayed available —
# is not a gate (P1-W4 false-green). This is the executed plant->red->revert the live
# kind run would otherwise be the only place to observe.
#
# Run: ci/kind/selftest/n2-upgrade-rehearsal-bite.sh   (exits non-zero on any violation)
# CI:  the drill-bite job runs this (no cluster needed — it is the local bite proof for
#      the live upgrade-rehearsal drill's negative control).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"
CHECK="${KIND_DIR}/assertions/checks/n2-upgrade-rehearsal.sh"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

if [ ! -f "${CHECK}" ]; then
  echo "::error::n2-upgrade-rehearsal.sh not found at ${CHECK}" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- the FAKE kubectl ----------------------------------------------------------
# A stand-in `kubectl` on PATH simulating just enough of the CNPG Cluster + a worker
# pod running alembic + the psql probe pod + the api rolling restart. State lives in
# $FAKE_STATE: an `n1_dropped` flag set when a "DROP COLUMN n1_col" SQL is seen (the
# contract-too-early plant), and `api_replicas` (2, dropped to 1 on a scale). The seed
# table always has 8 rows (no data loss on the happy path); audit_log has a fixed
# count + max(seq) unchanged by the migration (audit intact).
FAKE_BIN="${WORK}/bin"
mkdir -p "${FAKE_BIN}"
cat > "${FAKE_BIN}/kubectl" <<'FAKE'
#!/usr/bin/env bash
# Fake kubectl for the n2-upgrade-rehearsal drill self-test. Deterministic, no cluster.
set -uo pipefail
S="${FAKE_STATE:?FAKE_STATE unset}"
joined="$*"
SEED_ROWS="${FAKE_SEED_ROWS:-8}"
AUDIT_COUNT="${FAKE_AUDIT_COUNT:-5}"
AUDIT_MAXSEQ="${FAKE_AUDIT_MAXSEQ:-5}"

# Any `exec -i` (the psql calls) is fed the DB password over stdin — DRAIN it so the
# drill's `printf | kubectl` pipe closes cleanly (no SIGPIPE under pipefail). Non -i
# execs (alembic / auto_rebuild) carry no stdin pipe, so never read there (would block).
case "${joined}" in
  *"exec -i "*) cat >/dev/null 2>&1 || true ;;
esac

case "${joined}" in
  *"get cluster"*)
    exit 0 ;;                                              # CNPG Cluster present
  *"get secret"*)
    echo "eA=="; exit 0 ;;                                 # base64("x") superuser pw
  *"get pods"*"worker"*)
    echo "netops-worker-drillfake"; exit 0 ;;              # a Running worker pod
  *"readyReplicas"*)
    printf '%s' "$(cat "${S}/api_replicas" 2>/dev/null || echo 2)"; exit 0 ;;
  *"get deploy -l"*"worker"*|*"get deploy "*"worker"*)
    echo "netops-worker-discovery"; exit 0 ;;              # one worker Deployment
  *"get deployment netops-api"*)
    exit 0 ;;                                              # api Deployment present (precondition)
  *"get statefulset"*)
    exit 0 ;;                                              # Neo4j present -> rebuild step runs
  *"apply"*|*"wait "*|*"rollout restart"*|*"rollout status"*|*"delete pod"*)
    exit 0 ;;
  *"scale "*"netops-api"*)
    echo 1 > "${S}/api_replicas"; exit 0 ;;                # forced-unavail: api below floor
  *"exec"*)
    # In-pod work. Three exec shapes: (1) alembic on the worker, (2) auto_rebuild on the
    # worker, (3) psql on the probe pod. Classify by the argv the drill assembled.
    if printf '%s' "${joined}" | grep -q 'auto_rebuild'; then
      exit 0                                               # post-upgrade re-projection ran clean
    fi
    if printf '%s' "${joined}" | grep -q 'alembic'; then
      if printf '%s' "${joined}" | grep -q 'current'; then
        echo "0015_refresh_jti_reuse_detection (head)"     # alembic current
      fi
      exit 0                                               # alembic upgrade head OK
    fi
    # psql on the probe pod — answer by SQL.
    case "${joined}" in
      *"DROP COLUMN n1_col"*)
        : > "${S}/n1_dropped"; exit 0 ;;                   # the contract-too-early plant
      *"SELECT n1_col"*)
        if [ -f "${S}/n1_dropped" ]; then
          echo "ERROR:  column \"n1_col\" does not exist" >&2; exit 1   # N-1 reader breaks
        fi
        echo "n2-seed-1"; exit 0 ;;
      *"count(*) FROM netops_upgrade_drill_seed"*)
        echo "${SEED_ROWS}"; exit 0 ;;                     # no data loss (rows preserved)
      *"count(*) FROM audit_log"*)
        echo "${AUDIT_COUNT}"; exit 0 ;;
      *"max(seq)"*)
        echo "${AUDIT_MAXSEQ}"; exit 0 ;;
      *)
        exit 0 ;;                                          # CREATE/INSERT/ADD COLUMN/DROP TABLE
    esac
    ;;
  *)
    exit 0 ;;
esac
FAKE
chmod +x "${FAKE_BIN}/kubectl"

# --- scenario runner -----------------------------------------------------------
# Runs the REAL check with the fake kubectl first on PATH and the HA tier gate
# satisfied (HA=1). Extra env shapes the scenario (negative-control / force-unavail).
run_scenario() {
  local state; state="$(mktemp -d)"
  echo 2 > "${state}/api_replicas"
  local log="${WORK}/scenario.log"
  (
    export PATH="${FAKE_BIN}:${PATH}"
    # The bite SIMULATES the HA harness; the drill's HA!=1 tier gate must see HA=1 so it
    # RUNS and BITES here instead of skipping as a non-HA run (audit-W2 T7 F4).
    export HA=1
    export FAKE_STATE="${state}"
    export CHART_NS="netops"
    export N2_UPGRADE_ROLL_TIMEOUT_S="20"
    "$@"
    bash "${CHECK}"
  ) >"${log}" 2>&1
  local rc=$?
  LAST_LOG="${log}"
  return "${rc}"
}

# --- 1. POSITIVE — additive expand + rolling order + rebuild -> GREEN -----------
run_scenario true
rc_pos=$?
if [ "${rc_pos}" -eq 0 ]; then
  ok "POSITIVE path: additive EXPAND + rolling order + rebuild -> N-1 reader works, no data loss, audit intact, api held >=2 -> drill GREEN (exit 0)"
else
  bad "POSITIVE path FALSE-RED: the happy-path rehearsal exited ${rc_pos} (should be 0) — check ${LAST_LOG}"
  sed 's/^/    | /' "${LAST_LOG}" >&2 || true
fi

# --- 2. NEGATIVE CONTROL — contract-too-early drops n1_col -> N-1 reader RED -----
run_scenario export N2_UPGRADE_DRILL_NEGATIVE_CONTROL=1
rc_neg=$?
if [ "${rc_neg}" -ne 0 ]; then
  ok "NEGATIVE CONTROL: contract-too-early (DROP COLUMN n1_col) -> the N-1 reader breaks -> drill RED (exit ${rc_neg}) — the rolling-upgrade-without-downtime assertion BITES (ADR-0047 §2 / §10)"
else
  bad "FALSE-GREEN: the negative control (contract-too-early column drop) did NOT turn the drill red (exit 0) — the drill does not bite; it is not a gate (ADR-0047 §2)"
fi
# The bite must be the N-1 reader / expand-contract assertion specifically.
if grep -q "N-1 reader (SELECT n1_col) FAILED\|contract-too-early\|expand/contract §10 breach" "${LAST_LOG}"; then
  ok "negative-control RED is the N-1-reader / expand-contract assertion (not an incidental failure)"
else
  bad "negative-control turned red but NOT via the N-1-reader assertion — check the bite is attributable (${LAST_LOG})"
fi

# --- 3. AVAIL — api driven below the >=2-ready floor during the roll -> RED ------
run_scenario export N2_UPGRADE_DRILL_FORCE_API_UNAVAIL=1
rc_avail=$?
if [ "${rc_avail}" -ne 0 ]; then
  ok "AVAIL path: api driven below the >=2-ready floor during the roll -> drill RED (exit ${rc_avail}) — the no-downtime assertion bites on lost availability (G-MNT §346)"
else
  bad "FALSE-GREEN: driving the api below its availability floor during the roll passed (exit 0) — the no-downtime assertion does not bite"
fi
if grep -q "api availability DROPPED\|rolling upgrade without downtime VIOLATED" "${LAST_LOG}"; then
  ok "avail RED is the no-downtime availability assertion (not an incidental failure)"
else
  bad "avail turned red but NOT via the availability assertion — check the bite is attributable (${LAST_LOG})"
fi

echo "== n2-upgrade-rehearsal-bite summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::n2-upgrade-rehearsal bite proof found ${fails} violation(s)" >&2
  exit 1
fi
echo "n2-upgrade-rehearsal bite proof: the drill is GREEN on an additive-expand rolling upgrade and RED on a contract-too-early column drop / lost-availability roll (ADR-0047 §2 negative controls bite; G-MNT §346)."
