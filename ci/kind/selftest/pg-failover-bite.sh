#!/usr/bin/env bash
# EMPIRICAL, HARDWARE-FREE bite proof for the W4-T3 Postgres failover drill
# (ADR-0047 §2 — the negative-control rule; ADR-0042 §2 zero-committed-audit-loss).
#
# WHY THIS EXISTS (L1 + ADR-0047 §2): the failover drill (pg-failover.sh) runs LIVE
# only on a kind CNPG cluster, which CANNOT run on the authoring host (Windows, no
# Docker/Linux kind). ADR-0047 §2 nonetheless requires every drill's negative
# control be SHOWN to bite (plant → red → revert), never merely asserted. This
# self-test earns that proof WITHOUT a cluster: it runs the REAL pg-failover.sh
# check against a FAKE `kubectl` that simulates the CNPG cluster + in-pod psql, and
# asserts the OBSERVABLE polarity:
#   POSITIVE  — every committed row survives on the promoted primary  → drill GREEN (exit 0)
#   NEGATIVE  — the last committed (async) row is LOST on the promoted primary
#              (PG_FAILOVER_DRILL_NEGATIVE_CONTROL=1)                 → drill RED  (exit != 0)
#   NO-PROMOTE— the primary never changes (no automated promotion)    → drill RED
#   SLOW-RTO  — write restored but AFTER the RTO budget               → drill RED
#
# The NEGATIVE / NO-PROMOTE / SLOW-RTO scenarios are the planted regressions; the
# POSITIVE scenario is the revert-to-green. This is the executed plant→red→revert
# the live kind run would otherwise be the only place to observe (recorded here as
# a runnable proof; the live CI run corroborates it on the reduced-scale cluster).
#
# The fake kubectl interprets exactly the calls pg-failover.sh makes (get cluster,
# get secret, apply/wait/delete pod, get currentPrimary, exec -i … psql …) and
# serves canned rows from a state dir it mutates on the "kill". It reproduces the
# durability difference the drill measures: on the negative control the last row's
# COUNT/seq-gap/last-row/chain assertions see the lost row.
#
# Run: ci/kind/selftest/pg-failover-bite.sh   (exits non-zero on any violation)
# CI:  the `kind-harness-ha` job runs this (no cluster needed — it is the local
#      bite proof for the live drill's negative control).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"
CHECK="${KIND_DIR}/assertions/checks/pg-failover.sh"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

if [ ! -f "${CHECK}" ]; then
  echo "::error::pg-failover.sh not found at ${CHECK}" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- the FAKE kubectl ----------------------------------------------------------
# A stand-in `kubectl` on PATH that simulates just enough of the CNPG cluster +
# in-pod psql for pg-failover.sh. State lives in $FAKE_STATE (a dir): the current
# primary, a "killed" flag, and the row/seq/chain answers (mutated to model the
# lost row on the negative control). LOSE_LAST=1 tells the fake to drop the last
# committed row after the kill (the async-loss the negative control provokes).
FAKE_BIN="${WORK}/bin"
mkdir -p "${FAKE_BIN}"
cat > "${FAKE_BIN}/kubectl" <<'FAKE'
#!/usr/bin/env bash
# Fake kubectl for the pg-failover drill self-test. Deterministic, no cluster.
set -uo pipefail
S="${FAKE_STATE:?FAKE_STATE unset}"
# Read the full arg vector; we pattern-match the subcommands pg-failover.sh uses.
args=("$@")
joined="$*"

# helper: current primary (flips after the kill unless NO_PROMOTE=1)
current_primary() {
  if [ -f "${S}/killed" ] && [ "${NO_PROMOTE:-0}" != "1" ]; then
    echo "netops-pg-2"          # promoted replica
  else
    echo "netops-pg-1"          # original primary
  fi
}

case "${joined}" in
  *"get cluster"*"jsonpath={.status.currentPrimary}"*|*"get cluster"*"currentPrimary"*)
    current_primary; exit 0 ;;
  *"get cluster"*)
    # precondition existence check
    exit 0 ;;
  *"get secret"*"jsonpath="*)
    # superuser password (base64 of a throwaway dev value — NOT a real secret)
    printf '%s' "ZHJpbGwtZGV2LXB3"; exit 0 ;;   # base64("drill-dev-pw")
  *"delete pod"*"--force"*|*"delete pod netops-pg"*)
    : > "${S}/killed"
    # SLOW_RTO: delay the promotion becoming write-able by recording kill time far
    # in the past is not possible; instead the fake's write-probe stays read-only
    # until SLOW_RTO_UNTIL passes (handled in the exec branch).
    if [ "${SLOW_RTO:-0}" = "1" ]; then
      echo "$(( $(date +%s) + 999 ))" > "${S}/writeable_at"   # effectively never within budget
    fi
    exit 0 ;;
  *"delete pod"*)
    exit 0 ;;
  *"apply -f"*|*"wait "*)
    exit 0 ;;
  *"exec -i"*)
    # In-pod psql. The SQL is the LAST arg. stdin carries the password (ignored
    # here). We answer only the -tA scalar queries the drill reads; DDL/DO blocks
    # and the write-probe return success (exit 0) with no stdout.
    #
    # State machine (models the drill's real timeline so the SAME assertions the
    # live cluster would evaluate are exercised):
    #   * before the last-before-kill INSERT  → committed set = SEED rows
    #   * after  the last-before-kill INSERT  → committed set = SEED+1 rows
    #   * after the KILL, on the negative control (LOSE_LAST=1) → the last row is
    #     LOST → committed set drops back to SEED (a 1-row tail loss + 1 seq gap).
    # `seed` marks the seed loop; `last-before-kill` marks the extra committed row.
    SEED="${SEED_ROWS_FAKE:-25}"
    lost=0
    if [ -f "${S}/killed" ] && [ "${LOSE_LAST:-0}" = "1" ]; then lost=1; fi
    committed="${SEED}"
    if [ -f "${S}/last_committed" ] && [ "${lost}" -eq 0 ]; then committed="$(( SEED + 1 ))"; fi
    sql="${args[${#args[@]}-1]}"
    case "${sql}" in
      *"pg_terminate_backend"*|*"pg_stat_replication"*)
        # DETERMINISTIC LOSS WINDOW: the live drill's negative control severs
        # streaming replication (terminates the walsenders) right before the async
        # commit so the just-committed row provably reaches no standby. In the fake
        # there is no real streaming to sever; the loss is modelled directly by
        # LOSE_LAST=1 (the tail row is dropped after the kill). This branch keeps
        # the fake faithful — it accepts the replication-sever statement the real
        # drill now issues in the negative control (a plain psql_super, no stdout
        # read) — so the self-test exercises the SAME call path the live drill runs.
        exit 0 ;;
      *"last-before-kill"*)
        # The extra committed row is being inserted → record it committed.
        : > "${S}/last_committed"
        exit 0 ;;
      *"_writecheck"*)
        # write-restore probe (INSERT): succeeds once promoted, unless SLOW_RTO
        # keeps the new primary read-only past the budget.
        if [ ! -f "${S}/killed" ]; then exit 1; fi          # nothing writable pre-promote
        if [ "${SLOW_RTO:-0}" = "1" ]; then
          now="$(date +%s)"; until_ts="$(cat "${S}/writeable_at" 2>/dev/null || echo 0)"
          [ "${now}" -lt "${until_ts}" ] && exit 1           # stays read-only → slow RTO
        fi
        exit 0 ;;
      *"WHERE seq ="*)
        # last-before-kill row present? 1 unless it was the lost tail row.
        if [ -f "${S}/last_committed" ] && [ "${lost}" -eq 0 ]; then echo "1"; else echo "0"; fi
        exit 0 ;;
      *"generate_series"*)
        # seq gap count: 1 gap when the last committed row was lost, else 0.
        if [ -f "${S}/last_committed" ] && [ "${lost}" -eq 1 ]; then echo "1"; else echo "0"; fi
        exit 0 ;;
      *"want_prev"*)
        # hash-chain break count. A dropped TAIL row leaves the surviving prefix's
        # links intact (0 breaks) — the negative control bites via COUNT/last-row/
        # gap, exactly like a real tail-loss. Modelled as 0 to stay faithful.
        echo "0"; exit 0 ;;
      *"max(seq)"*)
        echo "${committed}"; exit 0 ;;
      *"count(*)"*)
        echo "${committed}"; exit 0 ;;
      *)
        # DDL / CREATE EXTENSION / CREATE TABLE / seed DO block → succeed silently.
        exit 0 ;;
    esac
    ;;
  *)
    # Any other kubectl call the drill might make → succeed quietly.
    exit 0 ;;
esac
FAKE
chmod +x "${FAKE_BIN}/kubectl"

# --- scenario runner -----------------------------------------------------------
# Runs the REAL check with the fake kubectl first on PATH and a fast poll budget.
# Extra env (LOSE_LAST / NO_PROMOTE / SLOW_RTO / negative-control flag) shapes the
# scenario. Returns the check's exit status; captures its log for inspection.
run_scenario() {
  local state; state="$(mktemp -d)"
  local log="${WORK}/scenario.log"
  (
    export PATH="${FAKE_BIN}:${PATH}"
    export FAKE_STATE="${state}"
    export SEED_ROWS_FAKE="6"
    # keep the drill fast + deterministic
    export PG_FAILOVER_SEED_ROWS="6"
    export PG_FAILOVER_RTO_BUDGET_S="60"
    export PG_FAILOVER_PROMOTE_POLL_S="8"
    # scenario knobs passed through the environment
    "$@"
    bash "${CHECK}"
  ) >"${log}" 2>&1
  local rc=$?
  LAST_LOG="${log}"
  return "${rc}"
}

# --- 1. POSITIVE — every committed row survives → GREEN ------------------------
run_scenario true
rc_pos=$?
if [ "${rc_pos}" -eq 0 ]; then
  ok "POSITIVE path: all committed rows survive promotion → drill GREEN (exit 0)"
else
  bad "POSITIVE path FALSE-RED: the happy-path drill exited ${rc_pos} (should be 0) — check ${LAST_LOG}"
  sed 's/^/    | /' "${LAST_LOG}" >&2 || true
fi

# --- 2. NEGATIVE CONTROL — async last row LOST → RED (the bite) ----------------
run_scenario export PG_FAILOVER_DRILL_NEGATIVE_CONTROL=1 LOSE_LAST=1
rc_neg=$?
if [ "${rc_neg}" -ne 0 ]; then
  ok "NEGATIVE CONTROL: async last row lost on the promoted primary → drill RED (exit ${rc_neg}) — the zero-audit-loss assertion BITES (ADR-0047 §2)"
else
  bad "FALSE-GREEN: the negative control (lost committed row) did NOT turn the drill red (exit 0) — the drill does not bite; it is not a gate (ADR-0047 §2)"
fi
# The bite must be the ZERO-LOSS assertion specifically (not an unrelated error).
if grep -q "committed-audit LOSS\|was LOST on failover\|MISSING on the promoted primary\|seq GAP" "${LAST_LOG}"; then
  ok "negative-control RED is the zero-committed-audit-loss assertion (not an incidental failure)"
else
  bad "negative-control turned red but NOT via the zero-audit-loss assertion — check the bite is attributable (${LAST_LOG})"
fi

# --- 3. NO PROMOTION — primary never changes → RED ----------------------------
run_scenario export NO_PROMOTE=1
rc_np=$?
if [ "${rc_np}" -ne 0 ]; then
  ok "NO-PROMOTION path: no automated promotion observed → drill RED (exit ${rc_np}) — the ≤60s/automated-promotion assertion bites"
else
  bad "FALSE-GREEN: no promotion happened yet the drill passed (exit 0) — the promotion assertion does not bite"
fi

# --- 4. SLOW RTO — write restored but past the budget → RED -------------------
run_scenario export SLOW_RTO=1
rc_slow=$?
if [ "${rc_slow}" -ne 0 ]; then
  ok "SLOW-RTO path: promotion exceeds the RTO budget → drill RED (exit ${rc_slow}) — the ≤60s RTO assertion bites"
else
  bad "FALSE-GREEN: an over-budget RTO passed (exit 0) — the RTO assertion does not bite"
fi

echo "== pg-failover-bite summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::pg-failover bite proof found ${fails} violation(s)" >&2
  exit 1
fi
echo "pg-failover bite proof: the drill is GREEN on survival and RED on lost-row / no-promote / slow-RTO (ADR-0047 §2 negative control bites)."
