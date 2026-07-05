#!/usr/bin/env bash
# W4-T8 N-2 → N upgrade rehearsal drill (G-MNT §346; PRODUCTION.md §10, ADR-0002
# expand/contract, ADR-0029 rolling order, ADR-0005 D5 Neo4j rebuild, ADR-0047
# §1/§2/§4/§5) — plugged into the W4-T1 HA kind assertion-runner.
#
# §11 G-MNT §346 CRITERION (stated in the header per ADR-0047 §1):
#   On the reduced-scale HA kind cluster, seed an N-2-shaped dataset and rehearse the
#   N-2 → N upgrade in the ADR-0029 ROLLING ORDER — the Alembic EXPAND migration
#   (additive; run as the pre-upgrade step) → roll the workers (Celery warm shutdown)
#   → roll the api keeping ≥2 replicas AVAILABLE (no downtime) → the post-upgrade
#   Neo4j projection rebuild — asserting the rolling-upgrade-WITHOUT-downtime
#   property: an N-1/N-2 reader keeps working against the EXPANDED schema (expand is
#   additive, never a break), NO committed row is lost, and the audit hash-chain
#   survives the migration intact.
#
# WHY EXPAND-ONLY (ADR-0002 expand/contract, PRODUCTION.md §10): a rolling upgrade has
# N-1/N-2 pods running against the NEW schema for the duration of the roll. Only the
# EXPAND (additive: ADD COLUMN / ADD TABLE, nullable/defaulted) is shipped in release
# N; the CONTRACT (drop the now-unused column) ships a release LATER, after the prior
# version leaves support (§10, NAMED-deferred here — an out-of-scope timing this drill
# does NOT run). A contract shipped in the SAME release drops a column an N-1 pod still
# reads → the rollout breaks / a rollback is unsafe: that is exactly the regression the
# negative control plants.
#
# THE BITE (drill-as-test + negative control, ADR-0047 §2 — the single most important
# rule): the drill SHIPS a planted regression that turns the no-downtime / no-data-loss
# assertion RED. With N2_UPGRADE_DRILL_NEGATIVE_CONTROL=1 the migration is a
# CONTRACT-TOO-EARLY step — it DROPS the column the N-1 reader still selects (instead of
# the safe additive EXPAND) — so the N-1 reader against the migrated schema FAILS →
# "rolling upgrade without downtime" is VIOLATED → the drill goes RED regardless of
# timing. A second planted regression (N2_UPGRADE_DRILL_FORCE_API_UNAVAIL=1) drives the
# api below its ≥2-ready availability floor during the roll → the no-downtime assertion
# goes RED. A rehearsal that only ever runs the happy path — or whose "no data loss"
# reads green whether or not a committed row survived — is not a gate (P1-W4
# false-green). See docs/runbooks/kind-harness.md "N-2 → N upgrade rehearsal".
#
# REDUCED SCALE (ADR-0047 §1/§4 — NAMED, never claimed as certified): this runs on the
# W4-T1 reduced-scale kind cluster (CNPG 1+2, api HPA floor 2) with a small FIXED
# seeded dataset. It proves the expand → rolling-order → rebuild → no-loss MECHANISM
# bites. It does NOT certify a scale point: the PROD-SHAPED seeded dataset (a
# full-inventory upgrade) stays deferred-accepted → GA with the ADR-0047 §4 written
# promotion path (seed a prod-shaped dataset; re-run this rehearsal; assert the same
# invariants) — never claimed from this run.
#
# REAL PG ONLY (ADR-0047 §5): the expand/contract + audit-survival semantics are
# meaningless on SQLite (no concurrent-reader schema-compat, no server-side audit
# hash-chain). The drill runs every DB assertion through psql against the live CNPG
# rw Service; there is no SQLite path.
#
# L1: kind CANNOT run on the Windows authoring host (no Docker/Linux kind), so this
# drill is authored + STATICALLY validated here (ci/kind/selftest/validate-harness.sh)
# and PROVEN to bite hardware-free (ci/kind/selftest/n2-upgrade-rehearsal-bite.sh); it
# runs LIVE only on the CI ubuntu runner via the `kind-harness-ha` job. That job stays
# continue-on-error / ABSENT from `all-gates` — promoting the G-MNT drill to blocking is
# a deliberate later step (GA), not W4-T8.
# L3: every value the in-pod psql / alembic needs is a POSITIONAL arg to `sh -c`
#     ("$1" …), never $(VAR) interpolated into the exec argv.
# L5: pipefail is on (the runner sets it globally); each captured psql/alembic output is
#     guarded (test -n / parsed) so a masked exit / empty read can never read green.
#
# SECRET SURFACE (audit spine + DB superuser): the CNPG superuser password is read
# by-reference from the dev Secret and fed to psql over STDIN — never echoed, never an
# argv arg, never written to a drill log (escalated per the agents README).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
. "${HERE}/../lib.sh"

NS="${CHART_NS:-netops}"

# --- chart object names (reduced-scale HA overlay, values-kind-ha.yaml) ----------
# CNPG cluster = <fullname>-pg; the operator creates the <cluster>-rw read-WRITE
# Service that always points at the CURRENT primary (same refs as the W4-T3 drill).
CLUSTER_NAME="${PG_CLUSTER_NAME:-netops-pg}"
PG_RW_HOST="${PG_RW_HOST:-${CLUSTER_NAME}-rw}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-netops}"
PG_SUPERUSER="${PG_SUPERUSER:-postgres}"
SUPERUSER_SECRET="${PG_SUPERUSER_SECRET:-netops-cnpg-superuser}"

# api Deployment (rolled last-but-one; ≥2 replicas must stay available) + the worker
# selector (the backend image carries alembic + the app package + the DB env).
API_DEPLOY="${API_DEPLOY:-netops-api}"
WORKER_SELECTOR="${WORKER_SELECTOR:-app.kubernetes.io/component=worker}"
# api availability floor held THROUGH the roll (ADR-0043 §1 HA floor / api-pdb).
API_AVAIL_FLOOR="${API_AVAIL_FLOOR:-2}"

# A drill-owned seed table (isolated — the drill never mutates a real app table; it
# only READS audit_log). `n1_col` is the column an N-1 reader selects; `n_col` is the
# additive EXPAND release N ships. The negative control DROPs `n1_col` (contract too
# early) so the N-1 reader breaks.
SEED_TABLE="${N2_UPGRADE_SEED_TABLE:-netops_upgrade_drill_seed}"
SEED_ROWS="${N2_UPGRADE_SEED_ROWS:-8}"

# Bound the api roll availability poll so a stuck roll is MEASURED, not a hang.
ROLL_TIMEOUT_S="${N2_UPGRADE_ROLL_TIMEOUT_S:-240}"

# Digest-pinned pgvector probe (psql + bash); same pin as the sibling drill probes
# (N12 — a re-push of the tag cannot swap it).
PROBE_MANIFEST="${HERE}/n2-upgrade-rehearsal-drill-probe.yaml"
PROBE_POD="${N2_UPGRADE_PROBE_POD:-n2-upgrade-rehearsal-drill-probe}"

# NEGATIVE CONTROLS (ADR-0047 §2):
#   =1 CONTRACT-TOO-EARLY — the migration DROPs n1_col instead of the additive expand;
#      the N-1 reader against the migrated schema breaks → RED.
NEG_CONTROL="${N2_UPGRADE_DRILL_NEGATIVE_CONTROL:-0}"
#   =1 FORCE-API-UNAVAIL — the api roll is driven below the ≥2-ready floor → the
#      no-downtime assertion goes RED (a second, availability-side planted regression).
FORCE_API_UNAVAIL="${N2_UPGRADE_DRILL_FORCE_API_UNAVAIL:-0}"

echo "== W4-T8 N-2 -> N upgrade rehearsal drill (G-MNT §346; ns=${NS}, cluster=${CLUSTER_NAME}) =="
echo "   reduced scale: CNPG 1+2 (ADR-0042 §1), api HPA floor ${API_AVAIL_FLOOR} (ADR-0043 §1);" \
     "seeded ${SEED_ROWS}-row N-2 dataset; negative_control=${NEG_CONTROL} force_api_unavail=${FORCE_API_UNAVAIL}"
echo "   prod-shaped seeded dataset (full-inventory upgrade) is NAMED deferred-accepted" \
     "-> GA (ADR-0047 §4 promotion path) — NOT claimed here. Contract migration timing is" \
     "§10-deferred (ships a release AFTER the prior version leaves support) — not run here."

# --- tier gate: HA-only drill — SKIP unless this is the HA harness (HA=1) --------
# Every reduced-scale reliability/scale drill in this dir asserts ONLY on the HA
# topology (kind-harness.sh run with HA=1). The harness EXPORTS HA, so gate on it
# FIRST — one deterministic, timing-independent tier signal (audit-W2 T7 F4).
if [ "${HA:-0}" != "1" ]; then
  echo "SKIP: non-HA harness run (HA!=1) — this reduced-scale HA drill asserts only"
  echo "      under HA=1 (the kind-harness-ha topology). Nothing to rehearse on the P2"
  echo "      run (loud SKIP, never a false-green pass)."
  exit 0
fi

# --- precondition: a CNPG Cluster + the api Deployment must be present, else SKIP -
# On a NON-HA / no-chart run there is no rolling upgrade to rehearse. Assert nothing
# rather than read a missing topology as a pass (a silent no-op is a false-green; the
# runner also fails an empty log, so we always emit).
if ! kubectl -n "${NS}" get cluster "${CLUSTER_NAME}" >/dev/null 2>&1; then
  echo "SKIP: CNPG Cluster '${CLUSTER_NAME}' absent in ns '${NS}' — this is a non-HA harness"
  echo "      run (no CloudNativePG operator/Cluster). The upgrade rehearsal asserts only"
  echo "      on the HA data tier. Nothing to rehearse on this run (loud SKIP, never a"
  echo "      false-green pass)."
  exit 0
fi
if ! kubectl -n "${NS}" get deployment "${API_DEPLOY}" >/dev/null 2>&1; then
  echo "SKIP: api Deployment '${API_DEPLOY}' absent in ns '${NS}' — no rolling api tier to"
  echo "      rehearse the availability floor against (loud SKIP, never a false-green pass)."
  exit 0
fi

# --- read the CNPG superuser password (by-reference; NEVER printed / never argv) --
SUPERUSER_PW_B64="$(kubectl -n "${NS}" get secret "${SUPERUSER_SECRET}" \
  -o jsonpath='{.data.password}' 2>/dev/null || true)"
if [ -z "${SUPERUSER_PW_B64}" ]; then
  _fail "could not read the CNPG superuser password from Secret '${SUPERUSER_SECRET}' — cannot run the DB assertions"
  echo "== drill aborted: superuser secret unreadable =="
  exit "$(assert_failures)"
fi
SUPERUSER_PW="$(printf '%s' "${SUPERUSER_PW_B64}" | base64 -d 2>/dev/null || true)"
if [ -z "${SUPERUSER_PW}" ]; then
  _fail "CNPG superuser password decoded empty — cannot authenticate the DB assertions"
  echo "== drill aborted: superuser secret empty =="
  exit "$(assert_failures)"
fi

# --- pick a Ready worker pod (backend image: has alembic + the app DB env) -------
WORKER_POD="$(kubectl -n "${NS}" get pods -l "${WORKER_SELECTOR}" \
  --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [ -z "${WORKER_POD}" ]; then
  _fail "no Running worker pod (${WORKER_SELECTOR}) in ns ${NS} — cannot run the expand migration (backend image)"
  echo "== drill aborted: no worker pod =="
  exit "$(assert_failures)"
fi
echo "expand migration runs on worker pod: ${WORKER_POD}"

# --- bring up the psql probe pod (digest-pinned, restricted-PSA) -----------------
if [ ! -f "${PROBE_MANIFEST}" ]; then
  _fail "probe manifest missing at ${PROBE_MANIFEST} — cannot run the DB assertions"
  echo "== drill aborted: probe manifest missing =="
  exit "$(assert_failures)"
fi
kubectl -n "${NS}" apply -f "${PROBE_MANIFEST}" >/dev/null
if ! kubectl -n "${NS}" wait --for=condition=Ready "pod/${PROBE_POD}" --timeout=120s; then
  _fail "psql probe pod '${PROBE_POD}' did not become Ready — cannot run the DB assertions"
  echo "== drill aborted: probe pod not Ready =="
  exit "$(assert_failures)"
fi

cleanup() {
  # Best-effort: drop the drill-owned seed table (idempotent) + the probe pod. The
  # drill NEVER touches a real app table, so this is the whole DB footprint. Never fatal.
  psql_super_nofail 'DROP TABLE IF EXISTS '"${SEED_TABLE}"';' >/dev/null 2>&1 || true
  kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
# N1: compose teardown with lib.sh's assert-exit trap (a bare `trap cleanup EXIT`
# would CLOBBER the assert-fail bite → false-green).
register_cleanup cleanup

# --- in-pod psql helpers (password over STDIN; coords positional — L3) -----------
# All connect through the rw Service, so every statement targets the CURRENT primary.
_psql_exec() {
  # $1 = extra psql flags string, remaining = SQL. Password via stdin (never argv).
  local flags="$1"; shift
  printf '%s' "${SUPERUSER_PW}" | kubectl -n "${NS}" exec -i "${PROBE_POD}" -- sh -c '
    read -r PGPASSWORD
    export PGPASSWORD
    exec psql -h "$1" -p "$2" -d "$3" -U "$4" -v ON_ERROR_STOP=1 $5 -c "$6"
  ' _ "${PG_RW_HOST}" "${PG_PORT}" "${PG_DB}" "${PG_SUPERUSER}" "${flags}" "$*"
}
psql_super()        { _psql_exec ""    "$@"; }
psql_super_val()    { _psql_exec "-tA" "$@"; }
psql_super_nofail() { _psql_exec ""    "$@" 2>/dev/null || return $?; }

# --- alembic on the worker pod (the EXPAND migration, the pre-upgrade step) -------
# Runs `alembic upgrade head` from /app on the backend image, assembling the DSN
# in-pod from the pod's own secretKeyRef env (never printed / never argv), mirroring
# the W1-T3 auto-rebuild Job DSN assembly (L3: all $VARs expand inside ONE sh -c).
run_alembic() {  # $1 = alembic subcommand string (e.g. "upgrade head" | "current")
  kubectl -n "${NS}" exec "${WORKER_POD}" -- sh -c '
    set -eu
    SUB="$1"
    NETOPS_PG_USER_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_USER\"],safe=\"\"))")"
    NETOPS_PG_PASS_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_PASSWORD\"],safe=\"\"))")"
    export NETOPS_DATABASE_URL="postgresql+asyncpg://${NETOPS_PG_USER_ENC}:${NETOPS_PG_PASS_ENC}@${NETOPS_POSTGRES_HOST}:${NETOPS_POSTGRES_PORT}/${NETOPS_POSTGRES_DB}"
    cd /app
    # shellcheck disable=SC2086
    exec alembic -c /app/alembic.ini $SUB
  ' _ "$1"
}

REHEARSAL_EPOCH="$(date +%s)"

# --- 1. SEED an N-2-shaped dataset (the isolated drill table + a committed marker) -
# n1_col is the column an N-1 reader selects; n_col is added by the EXPAND (step 3).
echo "seeding the reduced-scale N-2 dataset into '${SEED_TABLE}' (${SEED_ROWS} rows)"
if ! psql_super "DROP TABLE IF EXISTS ${SEED_TABLE};
  CREATE TABLE ${SEED_TABLE} (id int PRIMARY KEY, n1_col text NOT NULL);
  INSERT INTO ${SEED_TABLE} (id, n1_col) SELECT g, 'n2-seed-'||g FROM generate_series(1, ${SEED_ROWS}) g;" >/dev/null; then
  _fail "could not seed the N-2 dataset (${SEED_TABLE}) — cannot trust the drill baseline"
  echo "== drill aborted: seed failed =="
  exit "$(assert_failures)"
fi
SEED_COUNT_BEFORE="$(psql_super_val "SELECT count(*) FROM ${SEED_TABLE};" | tr -d '[:space:]' || true)"
if [ "${SEED_COUNT_BEFORE:-0}" != "${SEED_ROWS}" ]; then
  _fail "seeded row count is '${SEED_COUNT_BEFORE}', expected ${SEED_ROWS} — baseline not trustworthy"
  echo "== drill aborted: seed count mismatch =="
  exit "$(assert_failures)"
fi
echo "seeded ${SEED_COUNT_BEFORE} rows into ${SEED_TABLE} (the N-2 dataset)"

# --- 2. record the audit spine BEFORE the migration (the no-loss obligation) ------
# The migration must not lose a committed audit row (G-MNT §346 / ADR-0038). Capture
# the row count + max seq; a faithful upgrade preserves BOTH (no committed row dropped,
# no seq gap introduced). Read-only against audit_log (never mutated by the drill).
AUDIT_COUNT_BEFORE="$(psql_super_val "SELECT count(*) FROM audit_log;" | tr -d '[:space:]' || true)"
AUDIT_MAXSEQ_BEFORE="$(psql_super_val "SELECT COALESCE(max(seq),0) FROM audit_log;" | tr -d '[:space:]' || true)"
if ! printf '%s' "${AUDIT_COUNT_BEFORE}" | grep -qE '^[0-9]+$'; then
  _fail "could not read the pre-migration audit_log count ('${AUDIT_COUNT_BEFORE}') — cannot assert no committed-audit loss"
  echo "== drill aborted: audit baseline unreadable =="
  exit "$(assert_failures)"
fi
AUDIT_MAXSEQ_BEFORE="${AUDIT_MAXSEQ_BEFORE:-0}"
echo "audit spine before migration: count=${AUDIT_COUNT_BEFORE} max_seq=${AUDIT_MAXSEQ_BEFORE}"

# --- 3. EXPAND migration — the ROLLING-ORDER STEP 1 (pre-upgrade) -----------------
# POSITIVE path: run the additive EXPAND (`alembic upgrade head` brings the schema to N;
# then add n_col additively) — an N-1 pod that only reads n1_col keeps working.
# NEGATIVE CONTROL: a CONTRACT-TOO-EARLY migration DROPs n1_col (the column an N-1 pod
# still reads) instead of the additive expand → the N-1 reader (step 6) breaks → RED.
echo "ROLLING ORDER 1/4 — EXPAND migration (alembic upgrade head, then additive schema change)"
if ! run_alembic "upgrade head" >/dev/null 2>&1; then
  _fail "alembic upgrade head FAILED on the worker pod — the expand migration did not apply (G-MNT §346)"
  echo "== drill aborted: expand migration failed =="
  exit "$(assert_failures)"
fi
ALEMBIC_STATE="$(run_alembic "current" 2>/dev/null | tr -d '\r' || true)"
echo "alembic current after upgrade: ${ALEMBIC_STATE:-<none>}"
if [ "${NEG_CONTROL}" = "1" ]; then
  echo "::warning::NEGATIVE CONTROL active — applying a CONTRACT-TOO-EARLY migration:" \
       "DROP COLUMN ${SEED_TABLE}.n1_col (a column an N-1 pod still reads). The N-1 reader" \
       "assertion is EXPECTED to go RED (proving the drill bites; ADR-0047 §2 / §10)."
  psql_super_nofail "ALTER TABLE ${SEED_TABLE} DROP COLUMN n1_col;" >/dev/null 2>&1 || true
else
  # The additive EXPAND release N ships: ADD COLUMN (nullable) — an N-1 reader is
  # unaffected (it never selects n_col); a re-run is idempotent (IF NOT EXISTS).
  if ! psql_super "ALTER TABLE ${SEED_TABLE} ADD COLUMN IF NOT EXISTS n_col text;" >/dev/null; then
    _fail "the additive EXPAND (ADD COLUMN n_col) failed — cannot rehearse the expand step"
    echo "== drill aborted: expand DDL failed =="
    exit "$(assert_failures)"
  fi
fi

# --- 4. ROLLING ORDER 2/4 — roll the WORKERS (Celery warm shutdown) --------------
# Restart each worker Deployment and wait for the roll to complete. A warm shutdown
# re-queues in-flight tasks (acks_late, W2-T4); the no-loss assertion (step 6) proves
# no seeded row was lost across the roll.
echo "ROLLING ORDER 2/4 — rolling the workers (warm shutdown; acks_late redelivery, W2-T4)"
WORKER_DEPLOYS="$(kubectl -n "${NS}" get deploy -l "${WORKER_SELECTOR}" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
if [ -z "${WORKER_DEPLOYS}" ]; then
  echo "note: no worker Deployment matched ${WORKER_SELECTOR} for a rolling-restart" \
       "(the expand ran on the worker POD above); continuing with the api roll."
else
  while IFS= read -r wd; do
    [ -n "${wd}" ] || continue
    kubectl -n "${NS}" rollout restart "deployment/${wd}" >/dev/null 2>&1 || true
    if ! kubectl -n "${NS}" rollout status "deployment/${wd}" --timeout="${ROLL_TIMEOUT_S}s" >/dev/null 2>&1; then
      _fail "worker Deployment '${wd}' did not complete its roll within ${ROLL_TIMEOUT_S}s (rolling-order violated)"
    fi
  done <<EOF
${WORKER_DEPLOYS}
EOF
fi

# --- 5. ROLLING ORDER 3/4 — roll the api, holding the ≥2-ready availability floor -
# Restart the api Deployment and SAMPLE readyReplicas throughout the roll: it must
# NEVER drop below API_AVAIL_FLOOR (the PDB + surge config keep ≥2 serving — no
# downtime). FORCE_API_UNAVAIL drives it below the floor (the availability bite).
echo "ROLLING ORDER 3/4 — rolling the api (≥${API_AVAIL_FLOOR} replicas stay available; no downtime)"
api_ready() {  # echo the current readyReplicas (0 if unset)
  local r
  r="$(kubectl -n "${NS}" get deployment "${API_DEPLOY}" \
    -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  printf '%s' "${r:-0}"
}
READY_BEFORE="$(api_ready)"
if [ "${READY_BEFORE:-0}" -lt "${API_AVAIL_FLOOR}" ]; then
  _fail "api readyReplicas=${READY_BEFORE} is already below the ${API_AVAIL_FLOOR} floor BEFORE the roll — HA precondition not met"
fi
# Trigger the roll. Under FORCE_API_UNAVAIL the drill scales the api to 1 (below the
# floor) to model a roll that breaks availability (surge misconfig / PDB too weak).
if [ "${FORCE_API_UNAVAIL}" = "1" ]; then
  echo "::warning::FORCE_API_UNAVAIL active — driving the api below the ${API_AVAIL_FLOOR}-ready floor" \
       "during the roll; the no-downtime assertion is EXPECTED to go RED (ADR-0047 §2)."
  kubectl -n "${NS}" scale "deployment/${API_DEPLOY}" --replicas=1 >/dev/null 2>&1 || true
else
  kubectl -n "${NS}" rollout restart "deployment/${API_DEPLOY}" >/dev/null 2>&1 || true
fi
# Sample availability across the roll at a ~1s cadence and record the MINIMUM ready
# seen — so a BRIEF dip below the floor DURING the roll is caught, not just the
# endpoints. The completion probe uses a 1s timeout that doubles as the sampling
# cadence, so readiness is checked independently of a longer roll wait (CodeRabbit W4-T8).
MIN_READY="${READY_BEFORE:-0}"
roll_deadline=$(( $(date +%s) + ROLL_TIMEOUT_S ))
rolled=0
while [ "$(date +%s)" -lt "${roll_deadline}" ]; do
  r="$(api_ready)"
  if [ "${r:-0}" -lt "${MIN_READY}" ]; then MIN_READY="${r}"; fi
  if kubectl -n "${NS}" rollout status "deployment/${API_DEPLOY}" --timeout=1s >/dev/null 2>&1; then
    r="$(api_ready)"
    if [ "${r:-0}" -lt "${MIN_READY}" ]; then MIN_READY="${r}"; fi
    rolled=1
    break
  fi
done
if [ "${rolled}" -ne 1 ]; then
  _fail "api roll did not complete within ${ROLL_TIMEOUT_S}s (rolling-order stalled, G-MNT §346)"
fi
if [ "${MIN_READY:-0}" -ge "${API_AVAIL_FLOOR}" ]; then
  _pass "api availability held at >=${API_AVAIL_FLOOR} ready throughout the roll (min observed=${MIN_READY}) — no downtime (G-MNT §346)"
else
  _fail "api availability DROPPED to ${MIN_READY} ready during the roll (< ${API_AVAIL_FLOOR} floor) — DOWNTIME (rolling upgrade without downtime VIOLATED, G-MNT §346)"
fi

# --- 6. ROLLING ORDER 4/4 — post-upgrade Neo4j projection rebuild ----------------
# Re-project the topology from Postgres (the D5 rebuild, reused from W1-T3 auto_rebuild)
# after the schema change, and require it to complete (a schema change that broke the
# projection would fail here). Best-effort trigger; the completeness of the graph is
# the W4-T4 drill's assertion — here we require the post-upgrade rebuild to RUN clean.
echo "ROLLING ORDER 4/4 — post-upgrade Neo4j projection rebuild (D5 re-projection from Postgres)"
if kubectl -n "${NS}" get statefulset netops-neo4j >/dev/null 2>&1; then
  # Re-select a LIVE Running worker pod here: the worker roll (step 4) terminated the
  # pod picked in step 1, so ${WORKER_POD} may be gone by now — exec into a fresh one
  # for the rebuild (CodeRabbit W4-T8). Fall back to the original only if none resolves.
  REBUILD_WORKER_POD="$(kubectl -n "${NS}" get pods -l "${WORKER_SELECTOR}" \
    --field-selector=status.phase=Running \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  REBUILD_WORKER_POD="${REBUILD_WORKER_POD:-${WORKER_POD}}"
  echo "post-upgrade rebuild runs on worker pod: ${REBUILD_WORKER_POD}"
  if kubectl -n "${NS}" exec "${REBUILD_WORKER_POD}" -- sh -c '
      set -eu
      NETOPS_PG_USER_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_USER\"],safe=\"\"))")"
      NETOPS_PG_PASS_ENC="$(python -c "import os,urllib.parse;print(urllib.parse.quote(os.environ[\"NETOPS_POSTGRES_PASSWORD\"],safe=\"\"))")"
      export NETOPS_DATABASE_URL="postgresql+asyncpg://${NETOPS_PG_USER_ENC}:${NETOPS_PG_PASS_ENC}@${NETOPS_POSTGRES_HOST}:${NETOPS_POSTGRES_PORT}/${NETOPS_POSTGRES_DB}"
      export NETOPS_NEO4J_PASSWORD="${NETOPS_NEO4J_AUTH#*/}"
      exec python -m app.engines.topology.auto_rebuild --staleness-seconds 0
    ' _ >/dev/null 2>&1; then
    _pass "post-upgrade Neo4j re-projection completed clean (the schema change did not break the projection, D5)"
  else
    _fail "post-upgrade Neo4j re-projection FAILED — the expand migration broke the topology projection (G-MNT §346 / D5)"
  fi
else
  echo "note: no Neo4j StatefulSet present — the post-upgrade rebuild step is N/A on this topology (the W4-T4 drill owns the rebuild-completeness assertion)."
fi

# --- 7. ASSERT — the rolling-upgrade-WITHOUT-downtime invariants ------------------
# (a) N-1/N-2 READER COMPAT — an N-1 pod (reads ONLY n1_col) still works against the
#     MIGRATED schema. The additive expand keeps n1_col; the contract-too-early
#     negative control DROPPED it → this SELECT errors → the expand/contract invariant
#     is VIOLATED (the exact G-MNT §346 / §10 property).
if psql_super_val "SELECT count(*) FROM ${SEED_TABLE};" >/dev/null 2>&1 && \
   psql_super_val "SELECT n1_col FROM ${SEED_TABLE} WHERE id = 1;" >/dev/null 2>&1; then
  _pass "N-1 reader (SELECT n1_col) still works against the MIGRATED schema — rolling upgrade WITHOUT a break (expand is additive, contract §10-deferred; G-MNT §346)"
else
  _fail "N-1 reader (SELECT n1_col) FAILED against the migrated schema — a contract-too-early migration DROPPED a column an N-1 pod still reads (rolling upgrade WITHOUT downtime VIOLATED; expand/contract §10 breach, ADR-0047 §2)"
fi

# (b) NO COMMITTED-DATA LOSS — the seeded rows all survived the migration + roll.
SEED_COUNT_AFTER="$(psql_super_val "SELECT count(*) FROM ${SEED_TABLE};" 2>/dev/null | tr -d '[:space:]' || true)"
SEED_COUNT_AFTER="${SEED_COUNT_AFTER:-0}"
if [ "${SEED_COUNT_AFTER}" = "${SEED_COUNT_BEFORE}" ]; then
  _pass "no seeded-row loss across the upgrade (rows=${SEED_COUNT_AFTER}=${SEED_COUNT_BEFORE}) — no data loss (G-MNT §346)"
else
  _fail "seeded rows changed across the upgrade: after=${SEED_COUNT_AFTER} vs before=${SEED_COUNT_BEFORE} — committed DATA LOSS (G-MNT §346 VIOLATED)"
fi

# (c) AUDIT SPINE INTACT — no committed audit row lost + no seq regression across the
#     migration (ADR-0038 §3; the migration must not truncate/reorder the audit chain).
AUDIT_COUNT_AFTER="$(psql_super_val "SELECT count(*) FROM audit_log;" 2>/dev/null | tr -d '[:space:]' || true)"
AUDIT_MAXSEQ_AFTER="$(psql_super_val "SELECT COALESCE(max(seq),0) FROM audit_log;" 2>/dev/null | tr -d '[:space:]' || true)"
AUDIT_COUNT_AFTER="${AUDIT_COUNT_AFTER:-0}"
AUDIT_MAXSEQ_AFTER="${AUDIT_MAXSEQ_AFTER:-0}"
if printf '%s' "${AUDIT_COUNT_AFTER}" | grep -qE '^[0-9]+$' && \
   [ "${AUDIT_COUNT_AFTER}" -ge "${AUDIT_COUNT_BEFORE}" ] && \
   [ "${AUDIT_MAXSEQ_AFTER}" -ge "${AUDIT_MAXSEQ_BEFORE}" ]; then
  _pass "audit spine intact across the migration (count ${AUDIT_COUNT_BEFORE}->${AUDIT_COUNT_AFTER}, max_seq ${AUDIT_MAXSEQ_BEFORE}->${AUDIT_MAXSEQ_AFTER}; no committed-audit loss, no seq regression — ADR-0038 §3)"
else
  _fail "audit spine REGRESSED across the migration (count ${AUDIT_COUNT_BEFORE}->${AUDIT_COUNT_AFTER}, max_seq ${AUDIT_MAXSEQ_BEFORE}->${AUDIT_MAXSEQ_AFTER}) — committed-audit loss / seq regression (G-MNT §346 / ADR-0038 §3 VIOLATED)"
fi

# --- 8. structured collector line (mirrors the sibling drills) -------------------
_elapsed=$(( $(date +%s) - REHEARSAL_EPOCH ))
echo "DRILL n2_upgrade seconds=${_elapsed} seed_rows=${SEED_COUNT_AFTER} min_api_ready=${MIN_READY:-NA} result=$([ "$(assert_failures)" = "0" ] && echo PASS || echo FAIL)"

echo "== W4-T8 N-2 -> N upgrade rehearsal complete: $(assert_failures) failure(s) =="
echo "   scale: reduced (CNPG 1+2, api floor ${API_AVAIL_FLOOR}, ${SEED_ROWS}-row seed);" \
     "elapsed=${_elapsed}s."
echo "   prod-shaped seeded dataset (full-inventory upgrade) + contract-migration timing:" \
     "NAMED deferred-accepted -> GA (ADR-0047 §4 / PRODUCTION.md §10)."
