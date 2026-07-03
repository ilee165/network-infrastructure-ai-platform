#!/usr/bin/env bash
# W4-T5 Worker-kill idempotency + Celery ≥99% success drill (G-REL §319/§320;
# ADR-0008 §5 acks_late, ADR-0043 §6, ADR-0020 four-eyes, ADR-0047 §1/§2/§3/§5)
# — plugged into the W4-T1 HA kind assertion-runner.
#
# §11 G-REL §319/§320 CRITERION (stated in the header per ADR-0047 §1):
#   A worker node KILLED MID-RUN → every side-effecting job (discovery/config
#   write, CR-gated config op, docs/backup gen) COMPLETES VIA RETRY with NO
#   DUPLICATE SIDE EFFECT — a single DB write, a single ChangeRequest execution, a
#   single audit row (the W2-T4 idempotency under acks_late + reject_on_worker_lost)
#   — AND Celery success ≥ 99% over the window. The CR four-eyes gate (ADR-0020)
#   MUST NOT be bypassed or double-executed on the retry. Asserted on REAL PG (the
#   kind CloudNativePG cluster), never SQLite (ADR-0047 §5 — SQLite hides the
#   write-lock / isolation / unique-constraint semantics this idempotency depends
#   on; the P2 lesson, which is why the property also lives in backend/tests/pg/
#   test_worker_idempotency_pg.py behind the blocking pg-integration job).
#
# HOW THE KILL IS EXERCISED: with task_acks_late + task_reject_on_worker_lost
# (celery_app.py, ADR-0008 §5) a task whose worker is force-killed mid-run is
# REDELIVERED — the message is re-queued and a surviving worker runs it AGAIN. The
# drill force-kills one worker pod (a real node-loss trigger, --force
# --grace-period=0), then drives the SAME side effect a SECOND time on a SURVIVING
# worker pod via the real W2-T4 code path (config._persist / ChangeRequestService /
# nightly_backup) — exactly the double-delivery the redelivery produces — and
# asserts the second delivery adds NO duplicate side effect.
#
# THE BITE (drill-as-test + negative control, ADR-0047 §2 — the single most
# important rule): the drill SHIPS a planted regression that turns its exactly-once
# assertion RED. With WORKER_KILL_DRILL_NEGATIVE_CONTROL=1 the in-pod probe DISABLES
# the idempotency guard (bypasses the content-addressed dedup / state-machine guard)
# so a re-delivered task DOUBLE-WRITES (two snapshot rows, two audit rows, a second
# CR execution transition) — exactly the ADR-0047 §2 worker-kill control ("remove
# acks_late / idempotency guard → a re-delivered task double-writes"). The
# exactly-once counts then read 2 (not 1) and the success rate collapses → the
# assertions go RED regardless of timing. A drill that only ever runs the happy
# path — or that never actually kills a worker — is not a gate (P1-W4 false-green).
# See docs/runbooks/kind-harness.md "Worker-kill idempotency drill".
#
# REDUCED SCALE (ADR-0047 §1/§4 — NAMED, never claimed as certified): this runs on
# the W4-T1 reduced-scale kind cluster with a small FIXED drill fixture (1 device,
# 2 drill users) and a compressed success-rate window (ATTEMPTS redeliveries,
# default 40 — NOT the certified 500-device / 30-day soak). It proves the
# worker-kill → complete-via-retry → exactly-once MECHANISM bites and that the
# success rate holds ≥ 99% over the compressed window. It does NOT certify a scale
# point: the certified-scale soak success rate over a 30-day calendar window
# (G-REL §315/§320) stays deferred-accepted → GA with the ADR-0047 §4 written
# promotion path (a sized cluster; run the calendar soak; assert ≥ 99% over 30
# days) — never claimed from this run.
#
# REAL PG ONLY (ADR-0047 §5): the exactly-once + four-eyes checks are meaningless on
# SQLite (single-writer, no true isolation / unique-constraint concurrency). They
# run against the kind CloudNativePG cluster, which IS real Postgres. The in-pod
# helper (worker_idem_probe.py) HARD-FAILS if database_url is not a postgresql URL.
# There is no SQLite path.
#
# L1: kind CANNOT run on the Windows authoring host (no Docker/Linux kind), so this
# drill is authored + STATICALLY validated here (ci/kind/selftest/validate-harness.sh)
# and PROVEN to bite hardware-free (ci/kind/selftest/worker-kill-idempotency-bite.sh);
# it runs LIVE only on the CI ubuntu runner via the `kind-harness-ha` job. That job
# stays continue-on-error / ABSENT from `all-gates` — promoting the G-REL drill to
# blocking is a deliberate later step (W5/GA), not W4-T5.
# L3: every value the in-pod python needs (the assembled Postgres DSN, the base64
#     helper source, the subcommand, the negative-control flag) is a POSITIONAL arg
#     to `sh -c` ("$1" …), never $(VAR) in the exec argv.
# L5: pipefail is on (the runner sets it globally); each captured in-pod output is
#     guarded (test -n / parsed) so a masked exit / empty read can never read green.
#
# SECRET SURFACE (side-effecting tasks touch the audit spine + DB creds, escalated
# per the agents README): the Postgres password is read INSIDE the pod from its own
# env (secretKeyRef, never printed), assembled into the DSN in the in-pod shell, and
# NEVER echoed, argv-passed, or written to a drill log. The base64 payload passed
# via argv is the probe HELPER SOURCE only — it carries no secret.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
. "${HERE}/../lib.sh"

NS="${CHART_NS:-netops}"

# Chart worker selector (backend image: has the app package + asyncpg + the config
# task code + the config/secret env to reach PG). The reduced-scale HA overlay runs
# a base worker + KEDA per-queue workers; we select any Running worker pod.
WORKER_SELECTOR="${WORKER_SELECTOR:-app.kubernetes.io/component=worker}"

# Reduced-scale knobs (STATED, ADR-0047 §1). ATTEMPTS redeliveries drive the
# compressed success-rate window; SUCCESS_FLOOR is the §320 ≥ 99% bar.
ATTEMPTS="${WORKER_IDEM_ATTEMPTS:-40}"
SUCCESS_FLOOR="${WORKER_IDEM_SUCCESS_FLOOR:-99}"

# NEGATIVE CONTROL (ADR-0047 §2): when =1, the in-pod probe disables the idempotency
# guard so a redelivery double-writes → the exactly-once / success-rate assertions
# go RED. Passed through to the pod as WORKER_IDEM_NEGATIVE_CONTROL.
NEG_CONTROL="${WORKER_KILL_DRILL_NEGATIVE_CONTROL:-0}"

PROBE_SCRIPT="${HERE}/worker_idem_probe.py"

echo "== W4-T5 Worker-kill idempotency + Celery ≥99% drill (G-REL §319/§320; ns=${NS}) =="
echo "   reduced scale: 1 drill device + 2 drill users; success window=${ATTEMPTS} redeliveries;" \
     "success floor=${SUCCESS_FLOOR}%; negative_control=${NEG_CONTROL}"
echo "   certified-scale soak success (30-day calendar window, G-REL §315/§320) is NAMED" \
     "deferred-accepted -> GA (ADR-0047 §4) — NOT claimed here."

# --- tier gate: HA-only drill — SKIP unless this is the HA harness (HA=1) --------
# Every reduced-scale reliability/scale drill in this dir asserts ONLY on the HA
# topology (kind-harness.sh run with HA=1). The harness EXPORTS HA, so gate on it
# FIRST — one deterministic, timing-independent tier signal for all drills.
# Historically each drill self-detected its tier by probing for a workload's
# PRESENCE; that is tier-AMBIGUOUS on the P2 harness (which still renders the
# api/neo4j/worker single-instance workloads) and TIMING-fragile for pod-Running
# probes — it fails-open or skips only by luck (audit-W2 T7 F4). The per-tier object
# check below stays as a secondary graceful-skip under HA=1.
if [ "${HA:-0}" != "1" ]; then
  echo "SKIP: non-HA harness run (HA!=1) — this reduced-scale HA drill asserts only"
  echo "      under HA=1 (the kind-harness-ha topology). Nothing to drill on the P2"
  echo "      run (loud SKIP, never a false-green pass)."
  exit 0
fi

# --- precondition: worker pods must be present, else SKIP LOUDLY ----------------
# On a NON-HA / no-worker harness run there is no worker to kill. Assert nothing
# rather than read a missing worker as a pass (a silent no-op is a false-green; the
# runner also fails an empty log, so we always emit).
if [ ! -f "${PROBE_SCRIPT}" ]; then
  _fail "worker_idem_probe.py helper missing at ${PROBE_SCRIPT} — the drill cannot probe"
  echo "== drill aborted: helper missing =="
  exit "$(assert_failures)"
fi

# Enumerate Running worker pods (sorted, stable). We need at least ONE to run the
# probe; if there are >= 2 we KILL one mid-run and drive the redelivery on another
# (a true worker-node-loss trigger). With exactly 1 we still kill it and use the
# Deployment/ReplicaSet-recreated replacement (a fresh pod name; acks_late redelivers
# to it), but the ideal reduced-scale HA overlay runs multiple workers.
mapfile -t WORKER_PODS < <(kubectl -n "${NS}" get pods -l "${WORKER_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort || true)
if [ "${#WORKER_PODS[@]}" -eq 0 ]; then
  echo "SKIP: no Running worker pod (${WORKER_SELECTOR}) in ns '${NS}' — this is a run"
  echo "      without the Celery worker tier. The worker-kill drill asserts only when"
  echo "      workers are deployed (the HA topology). Nothing to drill on this run"
  echo "      (loud SKIP, never a false-green pass)."
  exit 0
fi
echo "worker pods observed: ${WORKER_PODS[*]}"

# The pod we KILL mid-run (the first), and the pod we drive the redelivery on (the
# last — a SURVIVING worker if there is more than one). If there is only one worker,
# both are the same name and the probe runs on the recreated replacement below.
KILL_POD="${WORKER_PODS[0]}"
PROBE_POD="${WORKER_PODS[$(( ${#WORKER_PODS[@]} - 1 ))]}"

# base64 the (secret-free) helper source ONCE; passed as a positional arg to the
# in-pod sh -c (L3), decoded to /tmp (RO rootfs; /tmp is the writable scratch), and
# run so app.* resolves from the backend image without a PYTHONPATH change.
PROBE_B64="$(base64 "${PROBE_SCRIPT}" | tr -d '\n')"

# --- in-pod probe runner -------------------------------------------------------
# Runs `python /tmp/worker_idem_probe.py <sub>` inside a worker pod. The DSN is
# assembled IN-POD from the pod's own secretKeyRef env (never printed / never argv),
# mirroring the W4-T4 rebuild drill's DSN assembly exactly (L3: all $VARs expand
# inside ONE sh -c; percent-encode user/pass). The negative-control flag is passed
# as a positional arg (never a secret). Echoes the probe's single `DRILL worker_idem
# <sub> …` line.
run_probe() {  # $1 = pod, $2 = subcommand
  local pod="$1" sub="$2"
  kubectl -n "${NS}" exec "${pod}" -- sh -c '
    set -eu
    SUB="$1"
    B64="$2"
    NEG="$3"
    ATT="$4"
    FLOOR="$5"
    printf "%s" "$B64" | base64 -d > /tmp/worker_idem_probe.py
    # Assemble NETOPS_DATABASE_URL from the config-map coords + the secret password
    # (the worker env carries NETOPS_POSTGRES_* + the password secretKeyRef, but not
    # a ready DSN). Percent-encode user + password so a : / @ / % cannot corrupt the
    # authority. python is present on the backend image.
    NETOPS_PG_USER_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_USER\"],safe=\"\"))")"
    NETOPS_PG_PASS_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_PASSWORD\"],safe=\"\"))")"
    export NETOPS_DATABASE_URL="postgresql+asyncpg://${NETOPS_PG_USER_ENC}:${NETOPS_PG_PASS_ENC}@${NETOPS_POSTGRES_HOST}:${NETOPS_POSTGRES_PORT}/${NETOPS_POSTGRES_DB}"
    export WORKER_IDEM_NEGATIVE_CONTROL="$NEG"
    export WORKER_IDEM_ATTEMPTS="$ATT"
    export WORKER_IDEM_SUCCESS_FLOOR="$FLOOR"
    exec python /tmp/worker_idem_probe.py "$SUB"
  ' _ "${sub}" "${PROBE_B64}" "${NEG_CONTROL}" "${ATTEMPTS}" "${SUCCESS_FLOOR}"
}

# Parse a `<field>=<n>` value out of a probe line into a shell var.
parse_field() {  # $1 = full probe output, $2 = field
  printf '%s\n' "$1" | sed -n "s/.* $2=\([0-9][0-9]*\).*/\1/p" | head -1
}
# Parse the `result=PASS|FAIL` token.
parse_result() {  # $1 = full probe output
  printf '%s\n' "$1" | sed -n 's/.* result=\(PASS\|FAIL\).*/\1/p' | head -1
}

cleanup() {
  # Best-effort: purge the drill-owned rows (idempotent). Never fatal. Run on the
  # PROBE pod if it is still around; ignore errors (the pod may have been recreated).
  run_probe "${PROBE_POD}" purge >/dev/null 2>&1 || true
}
# N1: compose teardown with lib.sh's assert-exit trap (a bare `trap cleanup EXIT`
# would CLOBBER the assert-fail bite → false-green).
register_cleanup cleanup

# --- 1. SEED the fixed reduced-scale drill fixture into Postgres ----------------
echo "seeding the fixed drill fixture (1 device + 2 drill users) into Postgres (real PG)"
SEED_OUT="$(run_probe "${PROBE_POD}" seed || true)"
echo "${SEED_OUT}"
if [ "$(parse_result "${SEED_OUT}")" != "PASS" ]; then
  _fail "seed did not report PASS — cannot trust the drill baseline (out='${SEED_OUT}')"
  echo "== drill aborted: seed failed =="
  exit "$(assert_failures)"
fi

# --- 2. KILL a worker pod MID-RUN (a real node-loss trigger, acks_late redelivery)
# --force --grace-period=0 removes the worker immediately so any in-flight task is
# lost from that worker and REDELIVERED (task_reject_on_worker_lost, ADR-0008 §5).
# We do the kill BEFORE driving the redelivery on a surviving worker, so the
# exactly-once assertions below observe the state AFTER a worker actually died.
echo "KILLING worker pod ${KILL_POD} MID-RUN (--force --grace-period=0 → acks_late redelivery, ADR-0008 §5)"
kubectl -n "${NS}" delete pod "${KILL_POD}" --force --grace-period=0 --wait=false || true

# If the pod we planned to probe on is the one we killed (single-worker overlay),
# wait for a Running worker to reappear (the controller recreates it) and re-select.
if [ "${PROBE_POD}" = "${KILL_POD}" ]; then
  echo "single-worker overlay — waiting for a recreated Running worker to drive the redelivery on"
  deadline=$(( $(date +%s) + 180 ))
  while [ "$(date +%s)" -lt "${deadline}" ]; do
    NEWPOD="$(kubectl -n "${NS}" get pods -l "${WORKER_SELECTOR}" \
      --field-selector=status.phase=Running \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
    if [ -n "${NEWPOD}" ] && [ "${NEWPOD}" != "${KILL_POD}" ]; then
      PROBE_POD="${NEWPOD}"
      break
    fi
    sleep 3
  done
  if [ "${PROBE_POD}" = "${KILL_POD}" ]; then
    _fail "no surviving/recreated worker pod appeared within 180s of the kill — cannot drive the redelivery"
    echo "== drill aborted: no surviving worker =="
    exit "$(assert_failures)"
  fi
fi
echo "driving the redelivery + assertions on surviving worker pod: ${PROBE_POD}"

# --- 3. EXACTLY-ONCE — config capture double-delivery (kill + retry) ------------
# The probe delivers the SAME config twice (the kill + the acks_late retry) via the
# real config._persist path and reports the resulting snapshot + audit row counts.
# POSITIVE: content-addressed dedup → 1 snapshot + 1 audit row. NEGATIVE CONTROL:
# guard bypassed → 2 + 2 (double-write) → RED.
CAP_OUT="$(run_probe "${PROBE_POD}" capture || true)"
echo "${CAP_OUT}"
CAP_SNAP="$(parse_field "${CAP_OUT}" snapshots)"
CAP_AUD="$(parse_field "${CAP_OUT}" audits)"
if [ "${CAP_SNAP}" = "1" ] && [ "${CAP_AUD}" = "1" ]; then
  _pass "config capture redelivery is EXACTLY-ONCE: 1 snapshot row + 1 audit row (no duplicate side effect, G-REL §319)"
else
  _fail "config capture redelivery DUPLICATED a side effect: snapshots='${CAP_SNAP}' audits='${CAP_AUD}' (expected 1/1) — the worker-kill retry double-wrote (G-REL §319 VIOLATED; idempotency guard removed — ADR-0047 §2)"
fi

# --- 4. CR EXECUTION RETRY — no double-execute, four-eyes NOT bypassed ----------
# The probe drives a CR through the real four-eyes-gated lifecycle, claims it for
# execution TWICE (the kill + retry), and reports the transition + approval counts.
# POSITIVE: the state-machine guard makes the retry a ConflictError no-op → 1
# transition + 1 approval + gate held. NEGATIVE CONTROL: forced re-execution → 2
# transitions → RED.
CR_OUT="$(run_probe "${PROBE_POD}" cr-retry || true)"
echo "${CR_OUT}"
CR_TRANS="$(parse_field "${CR_OUT}" transitions)"
CR_APPR="$(parse_field "${CR_OUT}" approvals)"
CR_RESULT="$(parse_result "${CR_OUT}")"
if [ "${CR_TRANS}" = "1" ] && [ "${CR_APPR}" = "1" ] && [ "${CR_RESULT}" = "PASS" ]; then
  _pass "CR execution retry is idempotent AND four-eyes intact: 1 approved_to_executing transition + 1 approval, gate held (ADR-0020 not bypassed, G-REL §319)"
else
  _fail "CR execution retry regressed: transitions='${CR_TRANS}' approvals='${CR_APPR}' result='${CR_RESULT}' (expected 1/1/PASS) — the redelivered CR either DOUBLE-EXECUTED or the four-eyes gate was bypassed (ADR-0020 / G-REL §319 VIOLATED; ADR-0047 §2)"
fi

# --- 5. nightly_backup double-delivery — one started/finished pair, one fan-out --
# POSITIVE: ON CONFLICT DO NOTHING guard → the redelivery is 'skipped'; 1 started +
# 1 finished audit row, 1 fan-out wave. NEGATIVE control is exercised via the same
# guard-bypass path in the probe where applicable.
BK_OUT="$(run_probe "${PROBE_POD}" backup || true)"
echo "${BK_OUT}"
BK_RESULT="$(parse_result "${BK_OUT}")"
if [ "${BK_RESULT}" = "PASS" ]; then
  _pass "nightly_backup redelivery is EXACTLY-ONCE: one started+finished audit pair, one fan-out wave (config_backup_runs uniqueness guard, ADR-0043 §6)"
else
  _fail "nightly_backup redelivery DUPLICATED a side effect: '${BK_OUT}' — the same-run_id retry emitted a second audit pair / fan-out (G-REL §319 VIOLATED; ADR-0047 §2)"
fi

# --- 6. CELERY SUCCESS RATE ≥ 99% over the compressed window (G-REL §320) -------
# The probe drives ATTEMPTS redeliveries (each a worker-kill retry of the capture
# side effect) and reports how many completed exactly-once. POSITIVE: ~100%.
# NEGATIVE control: guard off → every redelivery double-writes → success collapses
# → RED (below the floor).
RATE_OUT="$(run_probe "${PROBE_POD}" rate || true)"
echo "${RATE_OUT}"
RATE_PCT="$(parse_field "${RATE_OUT}" success_pct)"
RATE_ATT="$(parse_field "${RATE_OUT}" attempts)"
RATE_OK="$(parse_field "${RATE_OUT}" succeeded)"
if [ -z "${RATE_PCT}" ] || [ -z "${RATE_ATT}" ]; then
  _fail "could not read the Celery success rate from the probe (out='${RATE_OUT}') — cannot assert G-REL §320"
elif [ "${RATE_PCT}" -ge "${SUCCESS_FLOOR}" ]; then
  _pass "Celery success rate = ${RATE_PCT}% (${RATE_OK}/${RATE_ATT}) >= ${SUCCESS_FLOOR}% over the compressed window (G-REL §320)"
else
  _fail "Celery success rate = ${RATE_PCT}% (${RATE_OK}/${RATE_ATT}) < ${SUCCESS_FLOOR}% — redeliveries did NOT complete exactly-once (G-REL §320 VIOLATED; idempotency guard removed — ADR-0047 §2)"
fi

# Emit the composite collector line (mirrors the W4-T3/T4 drills' DRILL … result=).
echo "DRILL worker_idem summary snapshots=${CAP_SNAP:-NA} audits=${CAP_AUD:-NA} transitions=${CR_TRANS:-NA} success_pct=${RATE_PCT:-NA} result=$([ "$(assert_failures)" = "0" ] && echo PASS || echo FAIL)"

echo "== W4-T5 worker-kill idempotency drill complete: $(assert_failures) failure(s) =="
echo "   scale: 1 drill device + 2 drill users; success window=${ATTEMPTS} redeliveries" \
     "(compressed); success floor=${SUCCESS_FLOOR}%."
echo "   certified-scale soak success (30-day calendar window, G-REL §315/§320):" \
     "NAMED deferred-accepted -> GA (ADR-0047 §4 promotion path)."
