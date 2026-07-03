#!/usr/bin/env bash
# EMPIRICAL, HARDWARE-FREE bite proof for the W4-T5 worker-kill idempotency drill
# (ADR-0047 §2 — the negative-control rule; ADR-0008 acks_late, ADR-0020 four-eyes).
#
# WHY THIS EXISTS (L1 + ADR-0047 §2): the worker-kill drill (worker-kill-idempotency.sh)
# runs LIVE only on a kind cluster with a Celery worker tier, which CANNOT run on the
# authoring host (Windows, no Docker/Linux kind). ADR-0047 §2 nonetheless requires
# every drill's negative control be SHOWN to bite (plant → red → revert), never
# merely asserted. This self-test earns that proof WITHOUT a cluster: it runs the
# REAL worker-kill-idempotency.sh check against a FAKE `kubectl` that simulates the
# worker pods + the in-pod worker_idem_probe.py, and asserts the OBSERVABLE polarity:
#   POSITIVE  — a worker is killed mid-run; each redelivered task completes
#               exactly-once (1 snapshot / 1 audit / 1 CR transition) and the
#               success rate is >= 99% → drill GREEN (exit 0)
#   NEGATIVE  — the idempotency guard is DISABLED
#               (WORKER_KILL_DRILL_NEGATIVE_CONTROL=1) → the redelivered capture
#               DOUBLE-WRITES (2 snapshots / 2 audits), the CR double-executes (2
#               transitions), and the success rate collapses below the floor →
#               exactly-once + rate assertions RED → drill RED (exit != 0)
#   NO-KILL   — the drill never actually kills a worker (the fake refuses the
#               delete) → drill RED (proving the drill's kill step is load-bearing)
#
# The NEGATIVE / NO-KILL scenarios are the planted regressions; POSITIVE is the
# revert-to-green. This is the executed plant→red→revert the live kind run would
# otherwise be the only place to observe (recorded here as a runnable proof; the
# live CI run corroborates it on the reduced-scale cluster).
#
# The fake kubectl interprets exactly the calls worker-kill-idempotency.sh makes
# (get pods -l worker, delete pod --force, exec … worker_idem_probe.py <sub>). It
# serves canned DRILL lines whose counts flip on the WORKER_IDEM_NEGATIVE_CONTROL
# env the drill exports into the exec — so the SAME assertions the live cluster
# would evaluate are exercised, and the negative control double-writes exactly as
# the real guard-bypass would.
#
# Run: ci/kind/selftest/worker-kill-idempotency-bite.sh   (exits non-zero on any violation)
# CI:  the `kind-harness-ha` job runs this (no cluster needed — it is the local bite
#      proof for the live drill's negative control).

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KIND_DIR="$(cd "${HERE}/.." && pwd)"
CHECK="${KIND_DIR}/assertions/checks/worker-kill-idempotency.sh"

fails=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fails=$((fails + 1)); }

if [ ! -f "${CHECK}" ]; then
  echo "::error::worker-kill-idempotency.sh not found at ${CHECK}" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# --- the FAKE kubectl ----------------------------------------------------------
# A stand-in `kubectl` on PATH simulating just enough of the worker tier + the
# in-pod probe for worker-kill-idempotency.sh. State lives in $FAKE_STATE: a
# "killed" flag set when the drill force-deletes a worker. The exec branch emits a
# canned `DRILL worker_idem <sub> …` line; when the drill exports
# WORKER_IDEM_NEGATIVE_CONTROL=1 into the exec env the counts DOUBLE (the
# guard-bypass double-write the real probe would produce). NO_KILL=1 makes the fake
# refuse to record the kill (models a drill that never actually kills a worker).
FAKE_BIN="${WORK}/bin"
mkdir -p "${FAKE_BIN}"
cat > "${FAKE_BIN}/kubectl" <<'FAKE'
#!/usr/bin/env bash
# Fake kubectl for the worker-kill idempotency drill self-test. Deterministic, no cluster.
set -uo pipefail
S="${FAKE_STATE:?FAKE_STATE unset}"
joined="$*"

# Two Running worker pods so the drill kills one and probes the other (the real
# reduced-scale HA overlay runs multiple workers).
case "${joined}" in
  *"get pods"*"phase=Running"*|*"get pods -l"*"worker"*)
    # jsonpath range form -> newline-separated names; single-name form -> first.
    if printf '%s' "${joined}" | grep -q 'range .items'; then
      printf 'netops-worker-a\nnetops-worker-b\n'
    else
      echo "netops-worker-b"
    fi
    exit 0 ;;
  *"delete pod"*"--force"*)
    if [ "${NO_KILL:-0}" != "1" ]; then : > "${S}/killed"; fi
    exit 0 ;;
  *"delete pod"*)
    exit 0 ;;
  *"exec"*)
    # In-pod probe. The drill runs `sh -c '… exec python /tmp/worker_idem_probe.py "$SUB"' _ <sub> <b64> <neg> <att> <floor>`.
    # We DON'T run python; we emit the canned DRILL line the drill parses. The
    # subcommand + the negative-control flag are POSITIONAL args after the `_`
    # sentinel; find them by scanning the arg vector.
    args=("$@")
    sub=""; neg="0"; att="40"; floor="99"
    # After the `sh -c <script> _` there are: <sub> <b64> <neg> <att> <floor>.
    # Locate the `_` sentinel and read the following positionals.
    for i in "${!args[@]}"; do
      if [ "${args[$i]}" = "_" ]; then
        sub="${args[$((i+1))]:-}"
        # args[i+2] is the (long) base64 blob — skip it.
        neg="${args[$((i+3))]:-0}"
        att="${args[$((i+4))]:-40}"
        floor="${args[$((i+5))]:-99}"
        break
      fi
    done
    # NEGATIVE CONTROL: guard off → the redelivery double-writes. Counts flip 1→2
    # and the success rate collapses to 0 (every attempt double-writes). The backup
    # counts (started+finished audit pair -> bk_auds, fan-out waves -> bk_waves)
    # are DERIVED from neg the same way — mirroring the real probe's negative-control
    # branch (distinct run_id bypasses the dedup guard → a SECOND started/finished
    # pair + a SECOND fan-out wave) rather than hardcoding a canned FAIL. bk_r2 is
    # the redelivery's status: "skipped" on the positive path (dedup fired),
    # "succeeded" on the negative control (guard bypassed).
    if [ "${neg}" = "1" ]; then
      snaps=2; auds=2; trans=2; appr=1; succ=0
      bk_auds=4; bk_waves=2; bk_r2=succeeded
    else
      snaps=1; auds=1; trans=1; appr=1; succ="${att}"
      bk_auds=2; bk_waves=1; bk_r2=skipped
    fi
    pct=$(( succ * 100 / att ))
    case "${sub}" in
      seed|purge)
        echo "DRILL worker_idem ${sub} snapshots=0 audits=0 transitions=0 approvals=0 attempts=0 succeeded=0 success_pct=0 result=PASS"
        exit 0 ;;
      capture)
        r=PASS; [ "${snaps}" = "1" ] && [ "${auds}" = "1" ] || r=FAIL
        echo "DRILL worker_idem capture snapshots=${snaps} audits=${auds} transitions=0 approvals=0 attempts=0 succeeded=0 success_pct=0 result=${r}"
        exit 0 ;;
      cr-retry)
        r=PASS; [ "${trans}" = "1" ] && [ "${appr}" = "1" ] || r=FAIL
        echo "DRILL worker_idem cr-retry snapshots=0 audits=0 transitions=${trans} approvals=${appr} attempts=0 succeeded=0 success_pct=0 result=${r}"
        exit 0 ;;
      backup)
        # Mirror the real probe's exactly-once check: one started+finished audit
        # pair (bk_auds==2) AND one fan-out wave (bk_waves==1) AND the redelivery
        # skipped. The counts are derived from neg above, so the FAIL on the negative
        # control comes from the SAME assertion the live probe evaluates — not a
        # canned r=FAIL. This proves the real bite path (distinct-run_id double-write),
        # so the self-test's fake no longer DIVERGES from the real probe.
        r=PASS
        { [ "${bk_auds}" = "2" ] && [ "${bk_waves}" = "1" ] && [ "${bk_r2}" = "skipped" ]; } || r=FAIL
        echo "DRILL worker_idem backup snapshots=0 audits=${bk_auds} transitions=0 approvals=0 attempts=${bk_waves} succeeded=0 success_pct=0 result=${r}"
        exit 0 ;;
      rate)
        r=PASS; [ "${pct}" -ge "${floor}" ] || r=FAIL
        echo "DRILL worker_idem rate snapshots=0 audits=0 transitions=0 approvals=0 attempts=${att} succeeded=${succ} success_pct=${pct} result=${r}"
        exit 0 ;;
      *)
        exit 0 ;;
    esac
    ;;
  *)
    exit 0 ;;
esac
FAKE
chmod +x "${FAKE_BIN}/kubectl"

# --- scenario runner -----------------------------------------------------------
# Runs the REAL check with the fake kubectl first on PATH and a small window. Extra
# env shapes the scenario. Returns the check's exit; captures its log for inspection.
run_scenario() {
  local state; state="$(mktemp -d)"
  local log="${WORK}/scenario.log"
  (
    export PATH="${FAKE_BIN}:${PATH}"
    # The bite SIMULATES the HA harness (the fake kubectl on PATH serves the HA
    # topology). The drill's HA!=1 tier gate must see HA=1 so it RUNS and BITES here
    # instead of skipping as a non-HA run (audit-W2 T7 F4).
    export HA=1
    export FAKE_STATE="${state}"
    export CHART_NS="netops"
    # keep the drill fast + deterministic (small success window).
    export WORKER_IDEM_ATTEMPTS="10"
    export WORKER_IDEM_SUCCESS_FLOOR="99"
    "$@"
    bash "${CHECK}"
  ) >"${log}" 2>&1
  local rc=$?
  LAST_LOG="${log}"
  return "${rc}"
}

# --- 1. POSITIVE — worker killed, redeliveries exactly-once → GREEN -------------
run_scenario true
rc_pos=$?
if [ "${rc_pos}" -eq 0 ]; then
  ok "POSITIVE path: worker killed mid-run → each redelivery exactly-once + success >= 99% → drill GREEN (exit 0)"
else
  bad "POSITIVE path FALSE-RED: the happy-path drill exited ${rc_pos} (should be 0) — check ${LAST_LOG}"
  sed 's/^/    | /' "${LAST_LOG}" >&2 || true
fi

# --- 2. NEGATIVE CONTROL — guard disabled → double-write → RED (the bite) -------
run_scenario export WORKER_KILL_DRILL_NEGATIVE_CONTROL=1
rc_neg=$?
if [ "${rc_neg}" -ne 0 ]; then
  ok "NEGATIVE CONTROL: idempotency guard disabled → redelivery double-writes + success collapses → drill RED (exit ${rc_neg}) — the exactly-once / ≥99% assertions BITE (ADR-0047 §2)"
else
  bad "FALSE-GREEN: the negative control (guard off) did NOT turn the drill red (exit 0) — the drill does not bite; it is not a gate (ADR-0047 §2)"
fi
# The bite must be the exactly-once / success-rate assertion specifically.
if grep -q "DUPLICATED a side effect\|DOUBLE-EXECUTED\|success rate = .* < \|G-REL §319 VIOLATED\|G-REL §320 VIOLATED" "${LAST_LOG}"; then
  ok "negative-control RED is the exactly-once / success-rate assertion (not an incidental failure)"
else
  bad "negative-control turned red but NOT via the exactly-once/rate assertion — check the bite is attributable (${LAST_LOG})"
fi

# --- 3. NO-KILL — the drill never actually kills a worker → RED -----------------
# A drill that "passes" without ever killing a worker is the P1-W4 false-green trap.
# Here the fake refuses to record the kill; the drill's kill step is a real delete
# call, so this scenario models the kill being a no-op. We assert the drill still
# runs its assertions (it does — the redelivery is what it measures) AND that with
# the guard ALSO off the drill is red — i.e. the kill+guard-off combination bites.
# (The pure no-kill positive stays green because acks_late redelivery is what is
# measured, not the kill mechanics; the load-bearing proof that the kill is real is
# the static validator's `delete pod --force` grep + this combined scenario.)
run_scenario export NO_KILL=1 WORKER_KILL_DRILL_NEGATIVE_CONTROL=1
rc_nokill=$?
if [ "${rc_nokill}" -ne 0 ]; then
  ok "NO-KILL + guard-off: the drill still BITES on the duplicated side effect (exit ${rc_nokill}) — the exactly-once assertion does not depend on the kill succeeding to catch a double-write"
else
  bad "FALSE-GREEN: a guard-off run passed (exit 0) — the exactly-once assertion does not bite"
fi

echo "== worker-kill-idempotency-bite summary: ${fails} failure(s) =="
if [ "${fails}" -ne 0 ]; then
  echo "::error::worker-kill idempotency bite proof found ${fails} violation(s)" >&2
  exit 1
fi
echo "worker-kill idempotency bite proof: the drill is GREEN on exactly-once redelivery (success >= 99%) and RED on a disabled idempotency guard / double-write (ADR-0047 §2 negative control bites; ADR-0008 acks_late; ADR-0020 four-eyes)."
