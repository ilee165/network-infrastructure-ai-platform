#!/usr/bin/env bash
# W4-T7 Compressed-soak drill — §6 SLOs hold over the compressed window
# (G-REL §315 (compressed); ADR-0046 §1/§2/§6 (SLOs/burn-rate/alert-as-test),
#  ADR-0047 §1/§2/§3/§4 (reduced-scale mechanism proof + named ceiling)) —
# plugged into the W4-T1 HA kind assertion-runner.
#
# §11 G-REL §315 CRITERION (stated in the header per ADR-0047 §1):
#   Drive STEADY MIXED synthetic load (API reads + discovery/config/docs queue
#   jobs) over a COMPRESSED window and assert:
#     (a) SLOs HELD (ADR-0046 §1/§2): every §6 SLI the recording rules derive stays
#         WITHIN its error budget for the ENTIRE window, so NO multi-window
#         burn-rate alert (W3-T3) would fire. The drill computes the SAME SLIs the
#         W3-T2 recording rules do — the non-5xx availability ratio, the fraction of
#         reads exceeding the p95/p99 latency boundary, and the discovery success
#         ratio — from repeated api `/metrics` scrapes across the window, and
#         asserts each stays inside the budget the W3-T3 fast-burn (14.4x) tier
#         alerts on. A single sample inside budget is NOT enough; the assertion is
#         over the SUSTAINED window (the soak half of the SLO).
#     (b) NO SLOW RESOURCE REGRESSION (ADR-0047 §2 soak row): connection counts,
#         worker memory, and queue depth stay BOUNDED across the window — a leak
#         that would surface over 30 calendar days shows as a monotone upward TREND
#         at compressed scale. The drill samples PgBouncer server connections, the
#         worker RSS, and the Redis queue LLEN at the window's START and END and
#         FAILS if any grew beyond a bounded-growth tolerance (a trend → fail).
#
# THE BITE (drill-as-test + negative control, ADR-0047 §2 — the single most
# important rule): this drill SHIPS a planted regression that turns its assertions
# RED. With COMPRESSED_SOAK_DRILL_NEGATIVE_CONTROL=1 the drill INJECTS the exact
# SLO regression ADR-0046 §6 / the ADR-0047 §2 soak row name — an error-rate +
# latency perturbation on the synthetic load — so the availability + latency SLIs
# breach their budget over the window (a burn-rate breach → the alert WOULD fire),
# AND it injects a monotone resource growth (a leak) so the bounded-trend assertion
# also goes RED. A soak that only ever runs the happy path — or that "held" whether
# or not the SLOs were actually within budget / whether or not a leak grew — is not
# a gate (P1-W4 false-green). The SLO-held assertion is ADDITIONALLY proven to bite
# HARDWARE-FREE with a REAL `promtool test rules` over a soak-shaped timeseries
# (ci/kind/selftest/compressed-soak-slo.test.yaml): a healthy window fires NO
# burn-rate alert, a perturbed window DOES — the same recording-rule + alert files
# W3-T2/W3-T3 ship. See docs/runbooks/kind-harness.md "Compressed-soak drill".
#
# COMPRESSED WINDOW (STATED, ADR-0047 §1/§4 — why it is representative of the
# MECHANISM, not the calendar SLA): the soak runs for SOAK_WINDOW_S seconds (default
# 600 s = 10 min) of STEADY load, sampling the SLIs every SOAK_SAMPLE_INTERVAL_S
# (default 30 s) so the window carries MANY samples (not one). This proves the §6
# SLIs are MEASURABLE and HELD over a SUSTAINED run and that no resource leaks over
# that run — the compressed-soak MECHANISM. It is NOT the 30-day calendar soak.
#
# REDUCED SCALE + NAMED CEILING (ADR-0047 §1/§4 — NAMED, never claimed as
# certified): this runs on the W4-T1 reduced-scale kind cluster (CNPG 1+2,
# PgBouncer, Redis Sentinel, api HPA floor 2/ceiling 4, KEDA per-queue workers). The
# load is LOAD_VUS virtual users / a steady queue-job feed (tens, not the certified
# 100 users), over a COMPRESSED SOAK_WINDOW_S window (minutes, not 30 days). It
# proves the SLO-held + no-slow-regression MECHANISM bites at reduced scale; it does
# NOT certify the 30-DAY CALENDAR SOAK. The certified-scale ceiling — the 30-day
# calendar soak meeting all §6 SLOs (G-REL §315) — stays DEFERRED-ACCEPTED → GA /
# customer cluster with the ADR-0047 §4 written promotion path (a 30-day staging
# window on a sized cluster; run the calendar soak, assert §6 SLOs) — NEVER claimed
# here.
#
# L1: kind CANNOT run on the Windows authoring host (no Docker/Linux kind), so this
# drill is authored + STATICALLY validated here (ci/kind/selftest/validate-harness.sh)
# and PROVEN to bite hardware-free (ci/kind/selftest/compressed-soak-bite.sh, which
# also runs REAL `promtool test rules`); it runs LIVE only on the CI ubuntu runner
# via the `kind-harness-ha` job. That job stays continue-on-error / ABSENT from
# `all-gates` — promoting the G-REL soak drill to blocking is a deliberate later
# step (W5/GA), not W4-T7.
# L3: every value the in-pod redis-cli / loadgen / psql needs is a POSITIONAL arg to
#     `sh -c` / `bash -c` ("$1" …), never $(VAR) in the exec argv; the Redis/DB
#     password is fed over STDIN (never argv, never a visible arg in the pod
#     process list).
# L5: pipefail is on (the runner sets it globally); each captured in-pod output is
#     guarded (test -n / parsed) so a masked exit / empty read can never read green.
#
# SECRET SURFACE (the soak load path touches the DB pooler + Redis broker creds):
# the Redis password and the CNPG superuser password are read by-reference from
# their dev Secrets and fed to the in-pod client over STDIN — NEVER echoed, never an
# argv arg, never written to a drill log. Only non-secret coordinates are argv-passed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
. "${HERE}/../lib.sh"

NS="${CHART_NS:-netops}"

# --- object names (chart fullname = "netops"; ADR-0042/0043/0044 templates) -----
FULLNAME="${CHART_FULLNAME:-netops}"

# The api Deployment + Service (the /metrics source AND the read-load target).
API_DEPLOY="${API_DEPLOY_NAME:-${FULLNAME}-api}"
API_SVC="${API_SVC_NAME:-${FULLNAME}-api}"
API_PORT="${API_PORT:-8000}"
API_HEALTH_PATH="${API_HEALTH_PATH:-/health}"
API_METRICS_PATH="${API_METRICS_PATH:-/metrics}"

# The PgBouncer Pooler rw Service (ADR-0042 §4) — the connection-count trend source.
# The CNPG cluster + superuser secret (for the server-connection-count probe).
POOLER_RW_HOST="${POOLER_RW_HOST:-${FULLNAME}-pg-pooler-rw}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-netops}"
PG_SUPERUSER="${PG_SUPERUSER:-postgres}"
SUPERUSER_SECRET="${PG_SUPERUSER_SECRET:-netops-cnpg-superuser}"
SUPERUSER_PW_KEY="${PG_SUPERUSER_PW_KEY:-password}"

# Redis (Sentinel HA tier, ADR-0044). The queue jobs are LPUSHed into the Redis
# LISTs keyed by the queue name (the same keys the workers/KEDA read); the queue
# LLEN is the queue-depth trend source. Password by-reference from the platform
# Secret; databaseIndex 0 (values.yaml default).
REDIS_MASTER_POD_SELECTOR="${REDIS_MASTER_POD_SELECTOR:-app.kubernetes.io/component=redis}"
PLATFORM_SECRET="${PLATFORM_SECRET:-netops}"
REDIS_PW_KEY="${REDIS_PW_KEY:-redisPassword}"
REDIS_DB_INDEX="${REDIS_DB_INDEX:-0}"

# The worker Deployment whose RSS we trend (the leak witness). The discovery worker
# is the busiest under the mixed load; any queue worker Deployment works.
WORKER_DEPLOY="${WORKER_DEPLOY_NAME:-${FULLNAME}-worker-discovery}"
WORKER_POD_SELECTOR="${WORKER_POD_SELECTOR:-netops.io/celery-queue=discovery}"

# The mixed-load queues we steadily feed (a small steady backlog, NOT a burst — the
# burst is W4-T6; this is a SUSTAINED trickle so the workers do steady work over the
# window). We assert each stays BOUNDED (drains ≈ as fast as we feed → no backlog
# trend). Absent queues are skipped gracefully.
SOAK_QUEUES="${COMPRESSED_SOAK_QUEUES:-discovery config docs}"

# --- reduced-scale + compressed-window knobs (STATED, ADR-0047 §1) --------------
# SOAK_WINDOW_S: the compressed steady-load window (minutes, NOT 30 days).
# SOAK_SAMPLE_INTERVAL_S: SLI + resource sampling cadence (so the window carries
# MANY samples — the assertion is over the SUSTAINED window, not one reading).
SOAK_WINDOW_S="${COMPRESSED_SOAK_WINDOW_S:-600}"
SOAK_SAMPLE_INTERVAL_S="${COMPRESSED_SOAK_SAMPLE_INTERVAL_S:-30}"
# Steady API read load per sample cycle: LOAD_VUS concurrent virtual users firing
# LOAD_REQUESTS reads (tens — NOT the certified 100 users). Steady per cycle.
LOAD_VUS="${COMPRESSED_SOAK_LOAD_VUS:-10}"
LOAD_REQUESTS="${COMPRESSED_SOAK_LOAD_REQUESTS:-100}"
# Steady queue-job feed per sample cycle (a small trickle per soak queue).
QUEUE_FEED_PER_CYCLE="${COMPRESSED_SOAK_QUEUE_FEED_PER_CYCLE:-5}"

# --- §6 SLO budgets the soak asserts the SLIs stay within (ADR-0046 §2 fast tier).
# These MIRROR the W3-T2 recording rules / W3-T3 fast-burn (14.4x) thresholds so the
# drill's "SLO held" is the SAME condition "no burn-rate alert fires" the alerts
# encode. A window-wide SLI breaching one of these is a burn-rate breach → FAIL.
#   Availability: budget = 1-0.999 = 0.001; fast-burn breaches at 14.4*0.001 error
#                 ratio. We assert the WINDOW error ratio stays <= this.
#   Read latency p95 < 300 ms: budget = 0.05 of reads may exceed 0.3 s; fast-burn
#                 breaches at 14.4*0.05 too-slow fraction.
#   Discovery success >= 99%: budget = 1-0.99 = 0.01; fast-burn at 14.4*0.01.
# Expressed in PER-MILLE (integer math; bash has no floats). 1000 = 1.0.
AVAIL_ERR_BUDGET_PERMILLE="${COMPRESSED_SOAK_AVAIL_ERR_PERMILLE:-14}"      # 14.4*0.001 ≈ 0.0144
LATENCY_SLOW_FRAC_PERMILLE="${COMPRESSED_SOAK_LAT_SLOW_PERMILLE:-720}"     # 14.4*0.05  = 0.72
LATENCY_BOUNDARY_MS="${COMPRESSED_SOAK_LAT_BOUNDARY_MS:-300}"              # the p95 boundary (le=0.3)
DISCOVERY_ERR_BUDGET_PERMILLE="${COMPRESSED_SOAK_DISC_ERR_PERMILLE:-144}"  # 14.4*0.01 = 0.144

# --- bounded-resource-trend tolerances (ADR-0047 §2 soak row: a leak → a trend) --
# A bounded resource may WOBBLE but must not TREND UP over the window. We allow a
# small absolute headroom for steady-state noise; growth beyond it is a leak → FAIL.
CONN_GROWTH_TOLERANCE="${COMPRESSED_SOAK_CONN_GROWTH_TOLERANCE:-5}"        # PgBouncer server conns
WORKER_RSS_GROWTH_TOLERANCE_KB="${COMPRESSED_SOAK_RSS_GROWTH_TOLERANCE_KB:-51200}"  # 50 MiB
QUEUE_DEPTH_GROWTH_TOLERANCE="${COMPRESSED_SOAK_QUEUE_GROWTH_TOLERANCE:-20}"  # LLEN backlog

# NEGATIVE CONTROL (ADR-0047 §2): when =1, the drill INJECTS an SLO regression
# (error-rate + latency perturbation on the synthetic load → a burn-rate breach over
# the window) AND a monotone resource leak so its assertions go RED. Passed through
# to the in-pod probes as COMPRESSED_SOAK_NEG.
NEG_CONTROL="${COMPRESSED_SOAK_DRILL_NEGATIVE_CONTROL:-0}"

echo "== W4-T7 compressed-soak drill (§6 SLOs hold over the compressed window; G-REL §315 compressed; ns=${NS}) =="
echo "   compressed window: ${SOAK_WINDOW_S}s of STEADY mixed load, sampled every ${SOAK_SAMPLE_INTERVAL_S}s" \
     "(MANY samples — representative of the MECHANISM: SLIs measurable+held over a sustained run + no slow leak," \
     "NOT the 30-day calendar SLA); load=${LOAD_VUS} VUs/${LOAD_REQUESTS} reads per cycle + ${QUEUE_FEED_PER_CYCLE}" \
     "jobs/cycle across queues [${SOAK_QUEUES}]; negative_control=${NEG_CONTROL}"
echo "   certified-scale G-REL (30-day calendar soak meeting all §6 SLOs, §315) is NAMED deferred-accepted -> GA" \
     "(ADR-0047 §4 promotion path: a 30-day staging window on a sized cluster; run the calendar soak, assert §6 SLOs)" \
     "— NOT claimed here."

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

# --- precondition: the api Deployment must be present, else SKIP LOUDLY -----------
# On a NON-HA / no-chart harness run there is nothing to soak. Assert nothing rather
# than read a missing api as a pass (a silent no-op is a false-green; the runner also
# fails an empty log, so we always emit).
if ! kubectl -n "${NS}" get deploy "${API_DEPLOY}" >/dev/null 2>&1; then
  echo "SKIP: api Deployment '${API_DEPLOY}' absent in ns '${NS}' — this is a non-HA / no-chart"
  echo "      harness run. The compressed-soak drill drives steady load against the api + workers"
  echo "      and asserts the §6 SLOs hold; it asserts only under HA=1 (the reduced-scale HA"
  echo "      topology). Nothing to soak on this run (loud SKIP, never a false-green pass)."
  exit 0
fi

# --- secrets (by-reference; NEVER printed / never argv) --------------------------
REDIS_PW_VALUE="$(kubectl -n "${NS}" get secret "${PLATFORM_SECRET}" \
  -o "jsonpath={.data.${REDIS_PW_KEY}}" 2>/dev/null | base64 -d || true)"
PGPASSWORD_VALUE="$(kubectl -n "${NS}" get secret "${SUPERUSER_SECRET}" \
  -o "jsonpath={.data.${SUPERUSER_PW_KEY}}" 2>/dev/null | base64 -d || true)"
if [ -z "${REDIS_PW_VALUE}" ]; then
  _fail "could not read the Redis password from Secret '${PLATFORM_SECRET}' key '${REDIS_PW_KEY}' — cannot feed the soak queue jobs"
  echo "== drill aborted: no redis credential =="
  exit "$(assert_failures)"
fi
if [ -z "${PGPASSWORD_VALUE}" ]; then
  _fail "could not read the CNPG superuser password from Secret '${SUPERUSER_SECRET}' key '${SUPERUSER_PW_KEY}' — cannot sample the PgBouncer connection count"
  echo "== drill aborted: no db credential =="
  exit "$(assert_failures)"
fi

# --- a Redis pod to run redis-cli in (feed the queue jobs / read LLEN) -----------
REDIS_POD="$(kubectl -n "${NS}" get pods -l "${REDIS_MASTER_POD_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "${REDIS_POD}" ]; then
  _fail "no Running Redis pod (${REDIS_MASTER_POD_SELECTOR}) — cannot drive the steady soak queue feed"
  echo "== drill aborted: no redis pod =="
  exit "$(assert_failures)"
fi

# The soak probe pod (bash /dev/tcp loadgen + curl-free metrics scrape + psql for
# the connection-count probe; digest-pinned).
PROBE_POD="compressed-soak-drill-probe"
PROBE_MANIFEST="${HERE}/compressed-soak-drill-probe.yaml"

cleanup() {
  # Best-effort: drain the soak-fed queue items + delete the probe pod. DEL the BARE
  # keys the RPUSH calls actually wrote (each ${q}), so no soak items linger between
  # runs (matches the W4-T6 cleanup fix — no fictional prefix).
  for q in ${SOAK_QUEUES}; do
    redis_cli_nofail DEL "${q}" >/dev/null 2>&1 || true
  done
  kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=false || true
}
# N1: compose teardown with lib.sh's assert-exit trap (a bare `trap cleanup EXIT`
# would CLOBBER the assert-fail bite → false-green).
register_cleanup cleanup

# --- in-pod redis-cli (password over STDIN — secret hygiene; coords positional — L3)
# Each Redis command token is a SEPARATE positional arg to sh -c ("$2", "$3", …) —
# never word-split from a single string (L3). The password is fed over stdin.
redis_cli() {  # $@ = Redis command + args (each a separate word)
  printf '%s' "${REDIS_PW_VALUE}" | kubectl -n "${NS}" exec -i "${REDIS_POD}" -- sh -c '
    IFS= read -r RPW
    # AUTH via the REDISCLI_AUTH env var (resolves through /proc/<pid>/environ —
    # owner+root only), NOT -a on argv (world-readable in the pod PID namespace).
    export REDISCLI_AUTH="$RPW"
    exec redis-cli -p 6379 --no-auth-warning -n "$1" "$2" "$3" "$4" "$5" "$6" "$7" \
      "$8" "$9" "${10}" "${11}" "${12}" "${13}" "${14}" "${15}" "${16}" "${17}" "${18}" \
      "${19}" "${20}" "${21}" "${22}" "${23}" "${24}" "${25}" "${26}" "${27}" "${28}" \
      "${29}" "${30}" "${31}" "${32}" "${33}" "${34}" "${35}" "${36}" "${37}" "${38}"
  ' _ "${REDIS_DB_INDEX}" "$@"
}
redis_cli_nofail() { redis_cli "$@" 2>/dev/null || return $?; }

# LLEN of a queue list (the queue-depth trend signal). Echoes the integer, or a
# distinct error token so a failed exec is not silently read as "0".
queue_len() {  # $1 = queue/list name
  local out
  out="$(redis_cli LLEN "$1")" || { echo "QUEUE_LEN_ERR"; return 1; }
  printf '%s' "${out}" | tr -d '[:space:]'
}

# --- helper: PgBouncer server-side connection count (the connection trend) -------
# Opens ONE psql through the pooler and counts server backends CNPG holds for this
# app DB. Transaction-mode pooling should keep this bounded across the window; a
# monotone rise is a connection leak. Password over STDIN (never argv).
pgbouncer_server_conns() {
  local neg="${1:-0}" out
  out="$(printf '%s' "${PGPASSWORD_VALUE}" | kubectl -n "${NS}" exec -i "${PROBE_POD}" -- bash -c '
    set -u
    IFS= read -r PGPW || true
    export PGPASSWORD="$PGPW"
    PGHOST="$1"; PGPORT="$2"; PGDB="$3"; PGUSER="$4"
    psql "host=$PGHOST port=$PGPORT dbname=$PGDB user=$PGUSER sslmode=prefer connect_timeout=8" \
      -v ON_ERROR_STOP=1 -tAc "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database();" 2>/dev/null \
      | tr -d "[:space:]"
  ' _ "${POOLER_RW_HOST}" "${PG_PORT}" "${PG_DB}" "${PG_SUPERUSER}" 2>/dev/null || true)"
  # NEGATIVE CONTROL: model a connection leak — inflate the reported count so the
  # END sample trends far above the START sample WITHOUT touching the real pooler
  # (scope: one drill). The inflation grows with the sample index the caller passes.
  if [ "${neg}" = "1" ]; then
    printf '%s' "LEAK"
    return 0
  fi
  # A legitimate reading is always >=1 (pg_stat_activity counts this probe's own
  # backend), so an empty/failed read is a BROKEN probe, not a real 0 — emit an error
  # token the trend assertion fails on rather than a false bounded 0 (a probe that
  # measured nothing must not read as "no leak", ADR-0047 §2).
  [ -n "${out}" ] && printf '%s' "${out}" || printf '%s' "CONN_ERR"
}

# --- helper: worker RSS in KiB (the memory-leak trend) ---------------------------
# Reads the discovery worker pod's RSS from /proc via `kubectl top` if metrics-server
# is present, else from the pod's cgroup memory.current; falls back to a proc read.
# Any monotone rise beyond the tolerance is a memory leak. Non-secret; no creds.
worker_rss_kb() {
  local neg="${1:-0}" pod out
  pod="$(kubectl -n "${NS}" get pods -l "${WORKER_POD_SELECTOR}" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ "${neg}" = "1" ]; then
    printf '%s' "LEAK"
    return 0
  fi
  if [ -z "${pod}" ]; then printf '%s' "RSS_ERR"; return 0; fi
  # Prefer cgroup v2 memory.current (bytes) → KiB; robust without metrics-server.
  out="$(kubectl -n "${NS}" exec "${pod}" -- sh -c '
    if [ -r /sys/fs/cgroup/memory.current ]; then
      awk "{printf \"%d\", \$1/1024}" /sys/fs/cgroup/memory.current
    elif [ -r /sys/fs/cgroup/memory/memory.usage_in_bytes ]; then
      awk "{printf \"%d\", \$1/1024}" /sys/fs/cgroup/memory/memory.usage_in_bytes
    else
      echo 0
    fi
  ' 2>/dev/null | tr -d '[:space:]' || true)"
  # A running worker's cgroup memory is always >0, so an empty/failed exec is a broken
  # selector/exec, not a real 0 — emit an error token the trend assertion fails on.
  [ -n "${out}" ] && printf '%s' "${out}" || printf '%s' "RSS_ERR"
}

# --- the in-pod steady-load + SLI sampler (bash /dev/tcp, no k6/locust/curl dep) --
# One SAMPLE CYCLE: fire LOAD_VUS×(reads) at the api /health path over /dev/tcp,
# measuring per-request latency (ms) + HTTP status; scrape the api /metrics once for
# the discovery success counters; emit a single SLI line:
#   SOAK sample avail_err_permille=<n> slow_frac_permille=<n> disc_err_permille=<n> p95_ms=<n> reqs=<n>
# The availability error ratio (5xx+connect-fail / total) and the too-slow fraction
# (reads exceeding LATENCY_BOUNDARY_MS / total) are the SAME SLIs the W3-T2 recording
# rules derive; the discovery success ratio is read from the /metrics discovery
# counters if present. All params are POSITIONAL bash -c args (L3).
run_sample() {  # $1 host $2 port $3 read_path $4 metrics_path $5 vus $6 reqs $7 boundary_ms $8 neg
  local host="$1" port="$2" rpath="$3" mpath="$4" vus="$5" reqs="$6" boundary="$7" neg="$8"
  kubectl -n "${NS}" exec -i "${PROBE_POD}" -- bash -c '
    set -u
    HOST="$1"; PORT="$2"; RPATH="$3"; MPATH="$4"; VUS="$5"; REQS="$6"; BOUNDARY="$7"; NEG="$8"
    tmp="$(mktemp -d)"
    # One raw HTTP/1.1 GET over a TCP socket bash opens itself; echoes "<code> <ms>".
    one_request() {
      local t0 t1 ms line code path="$1"
      t0="${EPOCHREALTIME}"
      if exec 9<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
        printf "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "${path}" "${HOST}" >&9
        IFS= read -r line <&9 || line=""
        exec 9<&- 2>/dev/null || true
        exec 9>&- 2>/dev/null || true
        code="$(printf "%s" "${line}" | awk "{print \$2}")"
        [ -n "${code}" ] || code="000"
      else
        code="000"
      fi
      t1="${EPOCHREALTIME}"
      ms="$(awk -v a="${t0}" -v b="${t1}" "BEGIN{printf \"%d\", (b-a)*1000}")"
      # NEGATIVE CONTROL: inject a DETERMINISTIC SLO regression — every request is
      # forced to a synthetic 5xx AND a latency spike past the p95 boundary, so the
      # availability error ratio (→ 1000‰) and the too-slow fraction (→ 1000‰) both
      # breach their fast-burn budgets (14‰ / 720‰) over the window — a real
      # burn-rate breach, decisive at ANY sample size (not probabilistic, so the bite
      # never flakes). This models the error-rate + latency perturbation ADR-0046 §6
      # / the ADR-0047 §2 soak row name; it does NOT touch the real chart (scope: one
      # drill).
      if [ "${NEG}" = "1" ]; then
        code="503"; ms=$(( BOUNDARY + 500 ))
      fi
      echo "${code} ${ms}"
    }
    fire() {  # worker index
      local n="$1" i
      i="$n"
      while [ "$i" -le "$REQS" ]; do
        one_request "${RPATH}" >> "$tmp/w$n"
        i=$(( i + VUS ))
      done
    }
    w=1
    while [ "$w" -le "$VUS" ]; do fire "$w" & w=$(( w + 1 )); done
    wait
    total=0; err=0; slow=0; latf="$tmp/lat"; : > "$latf"
    for f in "$tmp"/w*; do
      [ -f "$f" ] || continue
      while read -r code ms; do
        total=$(( total + 1 ))
        echo "$ms" >> "$latf"
        case "$code" in 5*) err=$(( err + 1 ));; 000) err=$(( err + 1 ));; esac
        if [ "${ms:-0}" -gt "$BOUNDARY" ]; then slow=$(( slow + 1 )); fi
      done < "$f"
    done
    if [ "$total" -eq 0 ]; then
      echo "SOAK sample avail_err_permille=NA slow_frac_permille=NA disc_err_permille=NA p95_ms=NA reqs=0"
      rm -rf "$tmp"; exit 0
    fi
    avail_err=$(( err * 1000 / total ))
    slow_frac=$(( slow * 1000 / total ))
    idx="$(awk -v n="$total" "BEGIN{i=int(n*0.95); if(i<1)i=1; print i}")"
    p95="$(sort -n "$latf" | sed -n "${idx}p")"
    # Discovery success ratio from the api /metrics scrape (if the counters exist).
    # netops_discovery_runs_total{status="succeeded"} / netops_discovery_runs_total.
    # NEGATIVE CONTROL: also inject a discovery error rate above the fast-burn budget
    # (500‰ >> 144‰ threshold) so the discovery SLO assertion goes RED under the
    # negative control — proving the discovery assertion is NOT a tautological gate
    # (ADR-0047 §2: every assertion must have a planted regression that turns it RED).
    disc_err="NA"
    if [ "${NEG}" = "1" ]; then
      disc_err=500
    else
      metrics="$(
        if exec 8<>"/dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
          printf "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" "${MPATH}" "${HOST}" >&8
          cat <&8 2>/dev/null || true
          exec 8<&- 2>/dev/null || true
          exec 8>&- 2>/dev/null || true
        fi
      )"
      # Distinguish a BROKEN discovery-metrics path from a legitimately idle one so a
      # missing counter is not read as a healthy SLO (a false-green): METRICS_ERR when
      # /metrics is unreachable/empty, NOCTR when reachable but the discovery counter is
      # absent, NA when the counter is present but no runs happened this cycle (idle),
      # else the computed failed/partial ratio. The window loop treats NA + a numeric
      # ratio as valid readings and FAILS if the counter was NEVER present the window.
      if [ -z "${metrics}" ]; then
        disc_err="METRICS_ERR"
      elif printf "%s" "${metrics}" | grep -q "netops_discovery_runs_total"; then
        succ="$(printf "%s" "${metrics}" | awk "/^netops_discovery_runs_total\{.*status=\"succeeded\"/ {s+=\$NF} END{printf \"%d\", s}")"
        tot="$(printf "%s" "${metrics}" | awk "/^netops_discovery_runs_total\{/ {s+=\$NF} END{printf \"%d\", s}")"
        if [ "${tot:-0}" -gt 0 ]; then
          disc_err=$(( (tot - succ) * 1000 / tot ))
        fi
      else
        disc_err="NOCTR"
      fi
    fi
    echo "SOAK sample avail_err_permille=${avail_err} slow_frac_permille=${slow_frac} disc_err_permille=${disc_err} p95_ms=${p95} reqs=${total}"
    rm -rf "$tmp"
  ' _ "${host}" "${port}" "${rpath}" "${mpath}" "${vus}" "${reqs}" "${boundary}" "${neg}"
}

# --- bring up the probe pod ------------------------------------------------------
kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=true || true
kubectl -n "${NS}" apply -f "${PROBE_MANIFEST}"
kubectl -n "${NS}" wait --for=condition=Ready "pod/${PROBE_POD}" --timeout=120s

API_HOST="${API_SVC}.${NS}.svc.cluster.local"

# --- 0. START-of-window resource baseline (the trend anchors) --------------------
echo "recording START-of-window resource baseline (PgBouncer conns / worker RSS / queue depth)"
# Under the negative control the START values are hardcoded to 10/10240 by the END-of-window
# block (lines below); skip the real probe calls entirely to avoid a pointless kubectl exec
# that (a) logs a misleading "LEAK" sentinel, (b) could fail if the probe pod is not yet
# ready, and (c) is silently masked by || true — keeping the log consistent with the
# arithmetic that follows.
if [ "${NEG_CONTROL}" = "1" ]; then
  CONN_START="LEAK"
  RSS_START="LEAK"
else
  CONN_START="$(pgbouncer_server_conns 0 || true)"
  RSS_START="$(worker_rss_kb 0 || true)"
fi
declare -A QDEPTH_START
for q in ${SOAK_QUEUES}; do
  # Keep QUEUE_LEN_ERR / empty as a distinct token — a failed LLEN is a broken probe,
  # not a real 0; the trend assertion fails on it (a real depth of 0 is fine).
  QDEPTH_START["${q}"]="$(queue_len "${q}" || true)"
done
echo "  START: pgbouncer_conns=${CONN_START} worker_rss_kb=${RSS_START} queue_depths=[$(for q in ${SOAK_QUEUES}; do printf '%s=%s ' "${q}" "${QDEPTH_START[${q}]}"; done)]"

# --- 1. STEADY MIXED LOAD over the COMPRESSED WINDOW, sampling the SLIs ----------
# Each cycle: feed a small steady queue-job trickle + fire a steady API read load +
# scrape the SLIs. Accumulate the WORST (max) SLI error across the window — the SLO
# is HELD only if EVERY sample stayed within budget (the sustained-window assertion,
# not a single lucky reading).
echo "driving ${SOAK_WINDOW_S}s of STEADY mixed load, sampling §6 SLIs every ${SOAK_SAMPLE_INTERVAL_S}s"
SAMPLES=0
MAX_AVAIL_ERR=0
MAX_SLOW_FRAC=0
MAX_DISC_ERR=0
MAX_P95=0
SLI_READ_OK=0
DISC_OK=0   # set when any sample yielded a valid discovery reading (numeric ratio or NA/idle)
soak_deadline=$(( $(date +%s) + SOAK_WINDOW_S ))
# do-while: run at least ONE sample cycle before checking the deadline, so a
# sub-sample-interval window (or the wall-clock second ticking over between setting
# the deadline and the first check) never yields ZERO samples — a soak always takes
# at least one reading. The deadline is checked AFTER each cycle to end the window.
while :; do
  # (i) steady queue-job feed (a trickle per queue — NOT a burst).
  # mapfile captures the generated values into an array without word-splitting (L3:
  # no $(VAR) in exec argv — a glob or IFS char in output would corrupt unquoted expansion).
  for q in ${SOAK_QUEUES}; do
    mapfile -t _soak_vals < <(seq 1 "${QUEUE_FEED_PER_CYCLE}" | while read -r i; do printf 'w4t7-soak-%s\n' "$i"; done)
    redis_cli RPUSH "${q}" "${_soak_vals[@]}" >/dev/null 2>&1 || true
  done
  # (ii) steady API read load + SLI scrape.
  SAMPLE_OUT="$(run_sample "${API_HOST}" "${API_PORT}" "${API_HEALTH_PATH}" "${API_METRICS_PATH}" "${LOAD_VUS}" "${LOAD_REQUESTS}" "${LATENCY_BOUNDARY_MS}" "${NEG_CONTROL}" || true)"
  a="$(printf '%s\n' "${SAMPLE_OUT}" | sed -n 's/.* avail_err_permille=\([0-9NA]*\).*/\1/p' | head -1)"
  s="$(printf '%s\n' "${SAMPLE_OUT}" | sed -n 's/.* slow_frac_permille=\([0-9NA]*\).*/\1/p' | head -1)"
  d="$(printf '%s\n' "${SAMPLE_OUT}" | sed -n 's/.* disc_err_permille=\([0-9A-Z_]*\).*/\1/p' | head -1)"
  p="$(printf '%s\n' "${SAMPLE_OUT}" | sed -n 's/.* p95_ms=\([0-9NA]*\).*/\1/p' | head -1)"
  SAMPLES=$(( SAMPLES + 1 ))
  echo "  sample ${SAMPLES}: ${SAMPLE_OUT}"
  if [ -n "${a}" ] && [ "${a}" != "NA" ]; then
    SLI_READ_OK=1
    [ "${a}" -gt "${MAX_AVAIL_ERR}" ] && MAX_AVAIL_ERR="${a}"
  fi
  if [ -n "${s}" ] && [ "${s}" != "NA" ]; then
    [ "${s}" -gt "${MAX_SLOW_FRAC}" ] && MAX_SLOW_FRAC="${s}"
  fi
  # NA (counter present, idle) and a numeric ratio are both VALID discovery readings;
  # METRICS_ERR / NOCTR / empty mean the discovery-metrics path was unreadable this
  # sample and do NOT count (the window fails below if it was never readable).
  case "${d}" in
    NA) DISC_OK=1 ;;
    ''|*[!0-9]*) : ;;
    *) DISC_OK=1; [ "${d}" -gt "${MAX_DISC_ERR}" ] && MAX_DISC_ERR="${d}" ;;
  esac
  if [ -n "${p}" ] && [ "${p}" != "NA" ]; then
    [ "${p}" -gt "${MAX_P95}" ] && MAX_P95="${p}"
  fi
  # End the window once the deadline has passed (checked AFTER the guaranteed cycle).
  [ "$(date +%s)" -ge "${soak_deadline}" ] && break
  # (iii) let the workers drain the trickle before the next cycle (steady state).
  sleep "${SOAK_SAMPLE_INTERVAL_S}"
done
echo "soak window complete: ${SAMPLES} sample(s); worst-over-window avail_err=${MAX_AVAIL_ERR}‰ slow_frac=${MAX_SLOW_FRAC}‰ disc_err=${MAX_DISC_ERR}‰ p95=${MAX_P95}ms"

if [ "${SLI_READ_OK}" -ne 1 ] || [ "${SAMPLES}" -eq 0 ]; then
  _fail "the soak recorded NO readable SLI sample over the ${SOAK_WINDOW_S}s window (samples=${SAMPLES}) — cannot assert the §6 SLOs held (the load/metrics path is broken; a soak that measures nothing is a false-green)"
  echo "== drill aborted: no SLI samples =="
  exit "$(assert_failures)"
fi

# --- 2. ASSERT: §6 SLOs HELD over the window (no burn-rate alert would fire) ------
# (a) API availability: the window error ratio stayed within the fast-burn budget.
if [ "${MAX_AVAIL_ERR}" -le "${AVAIL_ERR_BUDGET_PERMILLE}" ]; then
  _pass "API availability SLO HELD over the ${SOAK_WINDOW_S}s window: worst error ratio ${MAX_AVAIL_ERR}‰ <= ${AVAIL_ERR_BUDGET_PERMILLE}‰ fast-burn budget — no NetopsApiAvailabilityFastBurn would fire (§6 row 1 / ADR-0046 §2)"
else
  _fail "API availability SLO BREACHED over the window: worst error ratio ${MAX_AVAIL_ERR}‰ EXCEEDS the ${AVAIL_ERR_BUDGET_PERMILLE}‰ fast-burn budget — a burn-rate alert WOULD fire (§6 row 1 / G-REL §315 VIOLATED)"
fi
# (b) API read latency p95: the too-slow fraction stayed within the fast-burn budget.
if [ "${MAX_SLOW_FRAC}" -le "${LATENCY_SLOW_FRAC_PERMILLE}" ]; then
  _pass "API read-latency SLO HELD over the window: worst too-slow (> ${LATENCY_BOUNDARY_MS}ms) fraction ${MAX_SLOW_FRAC}‰ <= ${LATENCY_SLOW_FRAC_PERMILLE}‰ fast-burn budget (worst p95=${MAX_P95}ms) — no NetopsApiReadLatencyP95FastBurn would fire (§6 row 2 / ADR-0046 §2)"
else
  _fail "API read-latency SLO BREACHED over the window: worst too-slow fraction ${MAX_SLOW_FRAC}‰ EXCEEDS the ${LATENCY_SLOW_FRAC_PERMILLE}‰ fast-burn budget (worst p95=${MAX_P95}ms) — a burn-rate alert WOULD fire (§6 row 2 / G-REL §315 VIOLATED)"
fi
# (c) Discovery success: the failed/partial ratio (from the /metrics discovery
#     counter) stayed within the fast-burn budget. DISC_OK is set only when at least
#     one sample yielded a VALID reading (a numeric ratio, or NA = counter present but
#     idle); if the counter was absent / /metrics unreadable EVERY sample the SLO is
#     UNMEASURED and fails (a broken discovery-metrics path must not read green — the
#     false-green ADR-0047 §2 forbids). MAX_DISC_ERR stays 0 when the counter was
#     present with no failed runs — within budget.
if [ "${DISC_OK}" -ne 1 ]; then
  _fail "Discovery success SLO could NOT be measured over the ${SOAK_WINDOW_S}s window — the netops_discovery_runs_total counter was absent or /metrics was unreadable EVERY sample (a broken discovery-metrics path reading within-budget is a false-green, not a healthy discovery SLO; §6 row 4 / ADR-0047 §2)"
elif [ "${MAX_DISC_ERR}" -le "${DISCOVERY_ERR_BUDGET_PERMILLE}" ]; then
  _pass "Discovery success SLO within budget over the window: worst failed/partial ratio ${MAX_DISC_ERR}‰ <= ${DISCOVERY_ERR_BUDGET_PERMILLE}‰ fast-burn budget (0‰ = the counter was present with no failed runs this window) — no NetopsDiscoverySuccessFastBurn would fire (§6 row 4 / ADR-0046 §2)"
else
  _fail "Discovery success SLO BREACHED over the window: worst failed/partial ratio ${MAX_DISC_ERR}‰ EXCEEDS the ${DISCOVERY_ERR_BUDGET_PERMILLE}‰ fast-burn budget — a burn-rate alert WOULD fire (§6 row 4 / G-REL §315 VIOLATED)"
fi

# --- 3. END-of-window resource sample + ASSERT: NO slow resource regression ------
# A leak that would surface over 30 calendar days shows here as a monotone rise from
# START to END at compressed scale. The negative control returns "LEAK" sentinels
# that force the trend RED.
echo "recording END-of-window resource sample + asserting bounded trends (no leak → no trend)"
# For the negative control, the START "LEAK" sentinel + an END that is numerically
# far above forces the delta assertion RED. Convert sentinels to concrete numbers
# that model a leak: START small, END large.
if [ "${NEG_CONTROL}" = "1" ]; then
  CONN_START=10;  CONN_END=$(( CONN_START + CONN_GROWTH_TOLERANCE + 20 ))
  RSS_START=10240; RSS_END=$(( RSS_START + WORKER_RSS_GROWTH_TOLERANCE_KB + 102400 ))
else
  CONN_END="$(pgbouncer_server_conns 0 || true)"
  RSS_END="$(worker_rss_kb 0 || true)"
fi
# A resource probe that could not take a real reading returns an explicit error token
# (CONN_ERR / RSS_ERR / QUEUE_LEN_ERR), NOT 0 — a failed probe is an UNMEASURED leak
# signal, not a bounded 0->0 trend, so each assertion below FAILS on a non-integer
# reading rather than silently normalising to 0 and reading green (a broken probe
# reading "no leak" is the false-green ADR-0047 §2 forbids; the SLI-read guard above
# only covers the /health load path, not these separate resource probes). A queue
# depth of 0 is a legitimate value; only the error token / empty is a failed read.
_is_uint() { case "$1" in ''|*[!0-9]*) return 1;; *) return 0;; esac; }
declare -A QDEPTH_END
for q in ${SOAK_QUEUES}; do
  if [ "${NEG_CONTROL}" = "1" ]; then
    QDEPTH_END["${q}"]=$(( ${QDEPTH_START[${q}]:-0} + QUEUE_DEPTH_GROWTH_TOLERANCE + 50 ))
  else
    QDEPTH_END["${q}"]="$(queue_len "${q}" || true)"
  fi
done
echo "  END:   pgbouncer_conns=${CONN_END} worker_rss_kb=${RSS_END} queue_depths=[$(for q in ${SOAK_QUEUES}; do printf '%s=%s ' "${q}" "${QDEPTH_END[${q}]}"; done)]"

# (a) PgBouncer server connections bounded.
if ! _is_uint "${CONN_START}" || ! _is_uint "${CONN_END}"; then
  CONN_DELTA="ERR"
  _fail "PgBouncer server-connection probe did NOT return a real reading (START=${CONN_START} END=${CONN_END}) — cannot assert a bounded connection trend (a failed probe is not a 0->0 pass; the connection-leak witness was never measured, ADR-0047 §2 soak)"
else
  CONN_DELTA=$(( CONN_END - CONN_START ))
  if [ "${CONN_DELTA}" -le "${CONN_GROWTH_TOLERANCE}" ]; then
    _pass "PgBouncer server-connection count BOUNDED over the window: ${CONN_START} -> ${CONN_END} (delta ${CONN_DELTA} <= ${CONN_GROWTH_TOLERANCE} tolerance) — no connection leak (ADR-0047 §2 soak / ADR-0042 §4)"
  else
    _fail "PgBouncer server-connection count TRENDED UP over the window: ${CONN_START} -> ${CONN_END} (delta ${CONN_DELTA} > ${CONN_GROWTH_TOLERANCE} tolerance) — a connection leak that would surface over calendar time (ADR-0047 §2 soak VIOLATED)"
  fi
fi
# (b) worker RSS bounded (memory leak witness).
if ! _is_uint "${RSS_START}" || ! _is_uint "${RSS_END}"; then
  RSS_DELTA="ERR"
  _fail "Worker RSS probe did NOT return a real reading (START=${RSS_START} END=${RSS_END}) — cannot assert a bounded memory trend (a failed probe is not a 0->0 pass; the memory-leak witness was never measured, ADR-0047 §2 soak)"
else
  RSS_DELTA=$(( RSS_END - RSS_START ))
  if [ "${RSS_DELTA}" -le "${WORKER_RSS_GROWTH_TOLERANCE_KB}" ]; then
    _pass "Worker RSS BOUNDED over the window: ${RSS_START}KiB -> ${RSS_END}KiB (delta ${RSS_DELTA}KiB <= ${WORKER_RSS_GROWTH_TOLERANCE_KB}KiB tolerance) — no memory leak (ADR-0047 §2 soak)"
  else
    _fail "Worker RSS TRENDED UP over the window: ${RSS_START}KiB -> ${RSS_END}KiB (delta ${RSS_DELTA}KiB > ${WORKER_RSS_GROWTH_TOLERANCE_KB}KiB tolerance) — a memory leak that would surface over calendar time (ADR-0047 §2 soak VIOLATED)"
  fi
fi
# (c) each soak queue depth bounded (a backlog trend = workers not keeping up = leak).
QUEUE_TRENDED=0
for q in ${SOAK_QUEUES}; do
  qs="${QDEPTH_START[${q}]:-}"; qe="${QDEPTH_END[${q}]:-}"
  if ! _is_uint "${qs}" || ! _is_uint "${qe}"; then
    QUEUE_TRENDED=$(( QUEUE_TRENDED + 1 ))
    _fail "Queue '${q}' depth probe did NOT return a real reading (START=${qs} END=${qe}) — cannot assert a bounded backlog trend (a failed LLEN is not a 0->0 pass, ADR-0047 §2 soak)"
    continue
  fi
  qd=$(( qe - qs ))
  if [ "${qd}" -le "${QUEUE_DEPTH_GROWTH_TOLERANCE}" ]; then
    _pass "Queue '${q}' depth BOUNDED over the window: ${qs} -> ${qe} (delta ${qd} <= ${QUEUE_DEPTH_GROWTH_TOLERANCE} tolerance) — the workers kept up with the steady feed (no backlog trend, ADR-0047 §2 soak)"
  else
    QUEUE_TRENDED=$(( QUEUE_TRENDED + 1 ))
    _fail "Queue '${q}' depth TRENDED UP over the window: ${qs} -> ${qe} (delta ${qd} > ${QUEUE_DEPTH_GROWTH_TOLERANCE} tolerance) — a growing backlog the workers cannot drain (a slow regression, ADR-0047 §2 soak VIOLATED)"
  fi
done

# Emit the composite collector line (mirrors the sibling drills' DRILL … result=).
echo "DRILL compressed_soak window_s=${SOAK_WINDOW_S} samples=${SAMPLES} max_avail_err_permille=${MAX_AVAIL_ERR} max_slow_frac_permille=${MAX_SLOW_FRAC} max_disc_err_permille=${MAX_DISC_ERR} max_p95_ms=${MAX_P95} conn_delta=${CONN_DELTA} rss_delta_kb=${RSS_DELTA} queue_trended=${QUEUE_TRENDED} result=$([ "$(assert_failures)" = "0" ] && echo PASS || echo FAIL)"

echo "== W4-T7 compressed-soak drill complete: $(assert_failures) failure(s) =="
echo "   scale: ${SOAK_WINDOW_S}s compressed window; ${LOAD_VUS} VUs/${LOAD_REQUESTS} reads + ${QUEUE_FEED_PER_CYCLE} jobs/queue per cycle (reduced) — the SLO-held + no-slow-regression MECHANISM, NOT the calendar SLA."
echo "   certified-scale G-REL §315 (30-day calendar soak meeting all §6 SLOs): NAMED deferred-accepted -> GA (ADR-0047 §4 promotion path)."
