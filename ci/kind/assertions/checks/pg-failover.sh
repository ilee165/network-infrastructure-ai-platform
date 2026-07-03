#!/usr/bin/env bash
# W4-T3 Postgres failover drill (G-REL §316, ADR-0042 §2/§3/§7, ADR-0047 §2/§3/§5)
# — plugged into the W4-T1 HA kind assertion-runner.
#
# §11 G-REL §316 CRITERION (stated in the header per ADR-0047 §1):
#   primary kill → AUTOMATED promotion, write service restored ≤ 60 s
#   (RTO measured FROM THE KILL, not from detection) AND
#   ZERO committed-audit-entry loss — every audit row committed before the kill
#   is present on the promoted primary, hash-chain-valid (each prev_hash links the
#   predecessor's entry_hash, ordered by seq, genesis for the first), with NO seq
#   gap. This is the ADR-0042 §2 quorum-synchronous audit-write guarantee: an audit
#   row committed with `SET LOCAL synchronous_commit=remote_apply` is acknowledged
#   only after >=1 replica holds the WAL, so the promoted replica already has it.
#
# THE BITE (drill-as-test + negative control, ADR-0047 §2 — the single most
# important rule): this drill SHIPS a planted regression that turns the
# zero-audit-loss assertion RED. With PG_FAILOVER_DRILL_NEGATIVE_CONTROL=1 the
# last audit row before the kill is committed ASYNC (`SET LOCAL
# synchronous_commit=off`) instead of quorum-sync. Crucially, the negative control
# does NOT rely on async-streaming TIMING to lose the row: at reduced kind scale
# the WAL for a tiny row can reach a standby in milliseconds, and CNPG promotes a
# standby that already holds it, so a naive async-commit-then-kill would be
# FALSE-GREEN (the row survives, zero-loss passes). Instead the negative control
# ENGINEERS a deterministic loss window — it TERMINATES the walsender backends on
# the primary (severing streaming to every standby) immediately BEFORE the async
# commit, then force-kills with no intervening sleep — so the just-committed row
# provably reaches NO standby and is LOST on the promoted primary, and the survival
# assertion goes RED regardless of timing. A drill that only ever runs the happy
# path — or whose negative control only-sometimes bites — is not a gate (P1-W4
# false-green). See docs/runbooks/kind-harness.md "Postgres failover drill".
#
# REDUCED SCALE (ADR-0047 §1/§4 — NAMED, never claimed as certified): this runs on
# the W4-T1 reduced-scale kind CNPG cluster (1 primary + 2 replicas = instances:3,
# the ADR-0042 §1 quorum MINIMUM — NOT reduced) with a handful (SEED_ROWS, default
# 25) of seeded audit-shaped rows. It proves the failover + zero-audit-loss
# MECHANISM bites; it does NOT certify a scale point. The certified-scale ceilings
# (500-device / 100-user / 5,000-device / 30-day soak; backups-only DR RPO≤5min /
# RTO≤1h, G-REL §318) stay deferred-accepted → GA with the ADR-0047 §4 written
# promotion path — never claimed from this run.
#
# REAL PG ONLY (ADR-0047 §5): the audit-survival check is meaningless on SQLite
# (no sync-commit / streaming replication / promotion semantics). It runs against
# the kind CloudNativePG cluster, which IS real Postgres. There is no SQLite path.
#
# L1: kind CANNOT run on the Windows authoring host (no Docker/Linux kind), so this
# drill is authored + STATICALLY validated here (ci/kind/selftest/validate-harness.sh)
# and runs LIVE only on the CI ubuntu runner via the `kind-harness-ha` job. That
# job stays continue-on-error / ABSENT from `all-gates` — promoting the G-REL drill
# to blocking is a deliberate later step (W5/GA), not W4-T3.
# LIVE NEGATIVE CONTROL — BITE PROOF vs CORROBORATION (review fix): the ADR-0047 §2
# proof-it-bites for this drill is the HARDWARE-FREE self-test (pg-failover-bite.sh),
# which is blocking within `kind-harness-ha` and deterministically exercises the
# assertion polarity. The LIVE kill/promote/measure path has NOT run on the authoring
# host (L1) and only CORROBORATES the drill on the CI runner. Because the live loss
# is now ENGINEERED (walsender-terminate above) rather than timing-dependent, a green
# live negative-control run is a real bite — but W5/GA MUST re-verify that engineered
# window on the actual CI CNPG topology BEFORE promoting this drill to blocking; until
# that live re-verification, treat the live negative-control result as ADVISORY, not
# as sufficient standalone proof for blocking promotion (see ADR-0047 §4 path +
# docs/runbooks/kind-harness.md "Postgres failover drill").
# L3: every value the in-pod psql needs is a POSITIONAL arg to `sh -c` ("$1" …),
#     never $(VAR) in the exec argv; the DB password is fed over STDIN (never argv).
# L5: pipefail is on (the runner sets it globally); each captured psql output is
#     guarded so a masked exit / empty read can never read green.
#
# SECRET SURFACE (audit spine + DB superuser): the CNPG superuser password is read
# by-reference from the dev Secret and fed to psql over stdin — NEVER echoed, never
# an argv arg (visible in the pod process list), never written to a drill log.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
. "${HERE}/../lib.sh"

NS="${CHART_NS:-netops}"
PROBE_POD="pg-failover-drill-probe"
PROBE_MANIFEST="${HERE}/pg-failover-drill-probe.yaml"

# CNPG object names (chart: cluster = <fullname>-pg; the operator creates the
# <cluster>-rw read-WRITE Service that always points at the CURRENT primary).
CLUSTER_NAME="${PG_CLUSTER_NAME:-netops-pg}"
PG_RW_HOST="${PG_RW_HOST:-${CLUSTER_NAME}-rw}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-netops}"
# The drill authenticates as the CNPG SUPERUSER (it creates + drops a drill-scoped
# table; the app owner has no DDL on audit_log by design). Dev secret (L4) is the
# chart-generated basic-auth Secret <fullname>-cnpg-superuser (username=postgres).
PG_SUPERUSER="${PG_SUPERUSER:-postgres}"
SUPERUSER_SECRET="${PG_SUPERUSER_SECRET:-netops-cnpg-superuser}"
SUPERUSER_PW_KEY="${PG_SUPERUSER_PW_KEY:-password}"

# Reduced-scale knobs (STATED, ADR-0047 §1). SEED_ROWS audit-shaped rows are seeded
# hash-chain-valid before the kill; RTO_BUDGET_S is the §316 ≤ 60 s write-restore
# RTO measured FROM THE KILL.
SEED_ROWS="${PG_FAILOVER_SEED_ROWS:-25}"
RTO_BUDGET_S="${PG_FAILOVER_RTO_BUDGET_S:-60}"
# How long to keep polling the rw service for the promoted primary to accept a
# write. Bounded ABOVE the RTO budget so a miss is measured (RTO > budget → FAIL),
# not a hang; a genuine no-promotion still terminates.
PROMOTE_POLL_S="${PG_FAILOVER_PROMOTE_POLL_S:-120}"

# NEGATIVE CONTROL (ADR-0047 §2): when =1, the last pre-kill row is committed ASYNC
# (synchronous_commit=off) so it can be lost on the promoted primary → RED.
NEG_CONTROL="${PG_FAILOVER_DRILL_NEGATIVE_CONTROL:-0}"

# The scratch table (audit-shaped: seq + prev_hash/entry_hash chain + canonical
# fields). Drill-scoped so the drill never mutates the real append-only audit_log
# (which REVOKEs UPDATE/DELETE and is range-partitioned) yet exercises the SAME
# sync-commit + hash-chain durability path the audit spine uses.
DRILL_TABLE="${PG_FAILOVER_DRILL_TABLE:-w4t3_audit_failover_drill}"

echo "== W4-T3 Postgres failover drill (G-REL §316; ns=${NS}, cluster=${CLUSTER_NAME}) =="
echo "   reduced scale: CNPG instances=3 (1 primary + 2 replicas, ADR-0042 §1 quorum minimum);" \
     "seed_rows=${SEED_ROWS}; RTO budget=${RTO_BUDGET_S}s (from kill); negative_control=${NEG_CONTROL}"
echo "   certified-scale failover (G-REL §318 backups-only DR RPO<=5m/RTO<=1h; 30-day soak)" \
     "is NAMED deferred-accepted -> GA (ADR-0047 §4) — NOT claimed here."

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

# --- precondition: a CNPG Cluster must be present, else SKIP LOUDLY -------------
# On a NON-HA harness run (no CNPG operator / Cluster) there is no failover to
# drill. Assert nothing rather than read a missing cluster as a pass (a silent
# no-op is a false-green; the runner also fails an empty log, so we always emit).
if ! kubectl -n "${NS}" get cluster "${CLUSTER_NAME}" >/dev/null 2>&1; then
  echo "SKIP: CNPG Cluster '${CLUSTER_NAME}' absent in ns '${NS}' — this is a non-HA"
  echo "      harness run (no CloudNativePG operator/Cluster). The failover drill"
  echo "      asserts only under HA=1 (the reduced-scale HA topology). Nothing to"
  echo "      drill on this run (loud SKIP, never a false-green pass)."
  exit 0
fi

# --- DB superuser password (by-reference; NEVER printed / never argv) -----------
PGPASSWORD_VALUE="$(kubectl -n "${NS}" get secret "${SUPERUSER_SECRET}" \
  -o "jsonpath={.data.${SUPERUSER_PW_KEY}}" 2>/dev/null | base64 -d || true)"
if [ -z "${PGPASSWORD_VALUE}" ]; then
  echo "::error::could not read the CNPG superuser password from Secret" \
       "'${SUPERUSER_SECRET}' key '${SUPERUSER_PW_KEY}' — cannot run the drill" \
       "(an existingSecret deployment uses a different Secret name; the dev/kind" \
       "path uses the chart-generated one)." >&2
  exit 1
fi

# --- bring up the psql probe pod (digest-pinned, restricted-PSA) ---------------
cleanup() {
  # Best-effort: drop the drill table (idempotent) then delete the probe pod. The
  # DROP runs through the rw service so it lands on whichever pod is primary now.
  psql_super_nofail 'DROP TABLE IF EXISTS '"${DRILL_TABLE}"';' || true
  kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=false || true
}
# N1: compose teardown with lib.sh's assert-exit trap (a bare `trap cleanup EXIT`
# would CLOBBER the assert-fail bite → false-green).
register_cleanup cleanup
kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=true || true
kubectl -n "${NS}" apply -f "${PROBE_MANIFEST}"
kubectl -n "${NS}" wait --for=condition=Ready "pod/${PROBE_POD}" --timeout=120s

# --- in-pod psql helpers -------------------------------------------------------
# The password is fed over STDIN (N11 — never a visible argv arg); connection
# params + SQL are positional `sh -c` args (L3 — never $(VAR) in the exec argv).
# All connect through the rw Service, so every statement targets the CURRENT
# primary (before OR after promotion) — that is what makes "write restored on the
# NEW primary" observable through a single stable endpoint.
#
# psql_super <sql>            : run SQL, return psql's exit status (fails on error,
#                              ON_ERROR_STOP=1). Output goes to the drill log.
# psql_super_val <sql>        : run a -tAc scalar query, ECHO the trimmed value on
#                              stdout, return status. Used for MAX(seq)/COUNT/etc.
# psql_super_nofail <sql>     : like psql_super but never fatal under set -e (used
#                              in cleanup + the write-restore poll).
_psql_exec() {
  # $1 = extra psql flags string, remaining = SQL. Password via stdin.
  local flags="$1"; shift
  printf '%s' "${PGPASSWORD_VALUE}" | kubectl -n "${NS}" exec -i "${PROBE_POD}" -- sh -c '
    IFS= read -r PGPASSWORD
    export PGPASSWORD
    exec psql \
      "host=$1 port=$2 dbname=$3 user=$4 sslmode=prefer connect_timeout=10" \
      -v ON_ERROR_STOP=1 $5 -c "$6"
  ' _ "${PG_RW_HOST}" "${PG_PORT}" "${PG_DB}" "${PG_SUPERUSER}" "${flags}" "$*"
}
psql_super()        { _psql_exec ""    "$@"; }
psql_super_val()    { _psql_exec "-tA" "$@"; }
psql_super_nofail() { _psql_exec ""    "$@" 2>/dev/null || return $?; }

# --- 0. current primary (the pod the kill targets) -----------------------------
primary_pod() {
  kubectl -n "${NS}" get cluster "${CLUSTER_NAME}" \
    -o jsonpath='{.status.currentPrimary}' 2>/dev/null || true
}
PRIMARY_BEFORE="$(primary_pod)"
if [ -z "${PRIMARY_BEFORE}" ]; then
  _fail "no currentPrimary on cluster ${CLUSTER_NAME} — cannot drill a failover"
  echo "== drill aborted: no primary =="
  exit "$(assert_failures)"
fi
echo "current primary BEFORE kill: ${PRIMARY_BEFORE}"

# --- 1. SEED audit-shaped rows, hash-chain-valid, QUORUM-SYNC ------------------
# The drill table mirrors the audit chain: seq (monotonic), prev_hash/entry_hash
# (32-byte digests). Each row's entry_hash = sha256(canonical || prev_hash) using
# pgcrypto's digest(); prev_hash = predecessor's entry_hash; the first row chains
# from the 32-zero-byte GENESIS. Rows are inserted UNDER a transaction-scoped
# advisory lock (mirroring the audit writer's MAX(seq)+1-under-lock) and committed
# with `SET LOCAL synchronous_commit=remote_apply` (ADR-0042 §2 — the quorum-sync
# audit path). This is the durability path whose survival the kill tests.
echo "seeding ${SEED_ROWS} hash-chain-valid audit-shaped rows (quorum-sync commit path)"
psql_super "
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
  DROP TABLE IF EXISTS ${DRILL_TABLE};
  CREATE TABLE ${DRILL_TABLE} (
    seq        bigint PRIMARY KEY,
    actor      text        NOT NULL,
    action     text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    prev_hash  bytea       NOT NULL,
    entry_hash bytea       NOT NULL
  );
"
# Seed loop: one transaction per row, each quorum-sync (remote_apply). Building the
# chain in SQL keeps the drill self-contained (no byte-exact JSON reproduction of
# chain.py needed — the SURVIVAL check re-verifies linkage, which is exactly the
# ADR-0038 structural invariant). genesis = 32 zero bytes.
psql_super "
  DO \$\$
  DECLARE
    i           int;
    v_prev      bytea := decode(repeat('00', 32), 'hex');
    v_canon     text;
    v_hash      bytea;
  BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('${DRILL_TABLE}'));
    SET LOCAL synchronous_commit = remote_apply;  -- ADR-0042 §2 quorum-sync audit path
    FOR i IN 1..${SEED_ROWS} LOOP
      v_canon := i::text || '|drill-actor|seed';
      v_hash  := digest(convert_to(v_canon, 'UTF8') || v_prev, 'sha256');
      INSERT INTO ${DRILL_TABLE} (seq, actor, action, prev_hash, entry_hash)
        VALUES (i, 'drill-actor', 'seed', v_prev, v_hash);
      v_prev := v_hash;
    END LOOP;
  END
  \$\$;
"

# Record the pre-kill committed watermark (COUNT + MAX(seq)). These are the numbers
# the survival check compares against — every one of these committed rows MUST be
# present on the promoted primary (zero loss).
SEEDED_COUNT="$(psql_super_val "SELECT count(*) FROM ${DRILL_TABLE};" | tr -d '[:space:]')"
SEEDED_MAX_SEQ="$(psql_super_val "SELECT coalesce(max(seq),0) FROM ${DRILL_TABLE};" | tr -d '[:space:]')"
echo "seeded (quorum-sync): count=${SEEDED_COUNT} max_seq=${SEEDED_MAX_SEQ}"
if [ "${SEEDED_COUNT}" != "${SEED_ROWS}" ]; then
  _fail "seed COUNT mismatch (got '${SEEDED_COUNT}', wanted ${SEED_ROWS}) — cannot trust the drill baseline"
  echo "== drill aborted: seed failed =="
  exit "$(assert_failures)"
fi

# --- 2. the JUST-BEFORE-KILL committed row (the row the negative control loses) --
# One more chained row is committed immediately before the kill. On the POSITIVE
# path it commits QUORUM-SYNC (remote_apply) → the promoted replica holds it →
# survives. On the NEGATIVE CONTROL it commits ASYNC (synchronous_commit=off) →
# the primary acks before the WAL reaches a replica → a kill in that window LOSES
# it on the promoted primary → the survival check goes RED (ADR-0047 §2 bite).
LAST_SEQ=$(( SEEDED_MAX_SEQ + 1 ))
if [ "${NEG_CONTROL}" = "1" ]; then
  COMMIT_MODE="off"
  echo "::warning::NEGATIVE CONTROL active — committing the last pre-kill row (seq=${LAST_SEQ})" \
       "with synchronous_commit=off (ASYNC). This row is EXPECTED to be LOST on the" \
       "promoted primary; the survival assertion is EXPECTED to go RED (proving the drill bites)."
  # DETERMINISTIC LOSS WINDOW (review fix — do NOT rely on async streaming timing).
  # At reduced kind scale the async WAL for a tiny row can stream to a standby in
  # milliseconds, and CNPG promotes a standby that already holds it — so a naive
  # async commit + kill can be FALSE-GREEN (the row survives, zero-loss passes).
  # To make the loss DETERMINISTIC we SEVER streaming replication to every standby
  # BEFORE the async commit: terminate the live walsender backends on the current
  # primary (pg_terminate_backend over every pid in pg_stat_replication — that view
  # lists exactly the active replication/walsender connections). With no walsender
  # attached the immediately-following
  # synchronous_commit=off row is acknowledged by the primary without its WAL
  # reaching ANY standby; the force-kill then follows with no intervening sleep, so
  # no standby can re-attach and re-stream that segment before it is promoted. The
  # just-committed row is therefore provably absent on the promoted primary — the
  # loss is engineered, not timing-dependent. (Positive path is untouched: it
  # commits quorum-sync remote_apply, which by definition waits for a replica.)
  echo "negative control: severing streaming replication (terminating walsenders on the primary)" \
       "so the async row provably does NOT reach any standby before the kill"
  psql_super "
    SELECT pg_terminate_backend(pid)
    FROM pg_stat_replication
    WHERE pid IS NOT NULL;
  "
else
  COMMIT_MODE="remote_apply"
  echo "committing the last pre-kill row (seq=${LAST_SEQ}) quorum-sync (remote_apply)"
fi
psql_super "
  DO \$\$
  DECLARE
    v_prev  bytea;
    v_canon text := '${LAST_SEQ}|drill-actor|last-before-kill';
    v_hash  bytea;
  BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('${DRILL_TABLE}'));
    SET LOCAL synchronous_commit = ${COMMIT_MODE};
    SELECT entry_hash INTO v_prev FROM ${DRILL_TABLE} ORDER BY seq DESC LIMIT 1;
    v_hash := digest(convert_to(v_canon, 'UTF8') || v_prev, 'sha256');
    INSERT INTO ${DRILL_TABLE} (seq, actor, action, prev_hash, entry_hash)
      VALUES (${LAST_SEQ}, 'drill-actor', 'last-before-kill', v_prev, v_hash);
  END
  \$\$;
"
# The full committed set the promoted primary MUST hold with zero loss.
PRE_KILL_COUNT="$(psql_super_val "SELECT count(*) FROM ${DRILL_TABLE};" | tr -d '[:space:]')"
PRE_KILL_MAX_SEQ="$(psql_super_val "SELECT coalesce(max(seq),0) FROM ${DRILL_TABLE};" | tr -d '[:space:]')"
EXPECT_COUNT=$(( SEED_ROWS + 1 ))
echo "committed BEFORE kill: count=${PRE_KILL_COUNT} max_seq=${PRE_KILL_MAX_SEQ} (expected count=${EXPECT_COUNT}, max_seq=${LAST_SEQ})"

# --- 3. KILL the primary — RTO CLOCK STARTS HERE (from kill, ADR-0042 §3) -------
# We start the RTO timer at the instant we issue the kill (the §316 RTO is measured
# FROM THE KILL, not from operator detection). --force --grace-period=0 removes the
# primary pod immediately so the operator must elect + promote a replica (automated,
# no manual step, ADR-0042 §3).
echo "KILLING primary pod ${PRIMARY_BEFORE} (RTO clock starts at kill, ADR-0042 §3 / §316)"
KILL_EPOCH="$(date +%s)"
kubectl -n "${NS}" delete pod "${PRIMARY_BEFORE}" --force --grace-period=0 --wait=false

# --- 4. MEASURE promotion + write-restore (poll the rw service) -----------------
# The rw Service always points at the CURRENT primary. Write service is "restored"
# when a WRITE (a real transaction, not just a read) succeeds through rw AND the
# operator reports a currentPrimary DIFFERENT from the killed pod (automated
# promotion, not the old primary transiently answering). Poll until both hold or
# the poll window elapses; RTO = first success epoch - kill epoch.
echo "polling rw service for AUTOMATED promotion + write-service restore..."
WRITE_RESTORED=0
RTO_S=""
poll_deadline=$(( KILL_EPOCH + PROMOTE_POLL_S ))
while [ "$(date +%s)" -lt "${poll_deadline}" ]; do
  now_primary="$(primary_pod)"
  # A write probe: create-if-missing a marker table + insert a row through rw. If
  # the new primary is writable this succeeds; on the old/uninitialized endpoint it
  # errors (read-only / connection refused) — nofail so the poll continues.
  if [ -n "${now_primary}" ] && [ "${now_primary}" != "${PRIMARY_BEFORE}" ]; then
    if psql_super_nofail "
      CREATE TABLE IF NOT EXISTS ${DRILL_TABLE}_writecheck (t timestamptz DEFAULT now());
      INSERT INTO ${DRILL_TABLE}_writecheck DEFAULT VALUES;
    "; then
      RTO_S=$(( $(date +%s) - KILL_EPOCH ))
      WRITE_RESTORED=1
      echo "write service RESTORED on NEW primary '${now_primary}' at RTO=${RTO_S}s (was '${PRIMARY_BEFORE}')"
      break
    fi
  fi
  sleep 2
done

# --- 5. ASSERT: automated promotion + write service ≤ 60 s (from kill) ----------
if [ "${WRITE_RESTORED}" -ne 1 ]; then
  _fail "write service NOT restored within ${PROMOTE_POLL_S}s of the kill — no automated promotion observed (G-REL §316)"
elif [ "${RTO_S}" -le "${RTO_BUDGET_S}" ]; then
  _pass "AUTOMATED promotion; write service restored in ${RTO_S}s <= ${RTO_BUDGET_S}s RTO (G-REL §316, from kill)"
else
  _fail "write service restored but RTO=${RTO_S}s EXCEEDS the ${RTO_BUDGET_S}s budget (G-REL §316)"
fi

# --- 6. ASSERT: ZERO committed-audit loss on the promoted primary --------------
# Even if promotion missed the RTO, still verify durability (a slow-but-lossless
# failover and a fast-but-lossy one are DIFFERENT failures — report both).
# (a) COUNT — every committed row present (no loss).
POST_COUNT="$(psql_super_val "SELECT count(*) FROM ${DRILL_TABLE};" | tr -d '[:space:]')"
if [ "${POST_COUNT}" = "${EXPECT_COUNT}" ]; then
  _pass "row COUNT on promoted primary = ${POST_COUNT} (all ${EXPECT_COUNT} committed rows survived — zero loss)"
else
  _fail "row COUNT on promoted primary = ${POST_COUNT}, expected ${EXPECT_COUNT} — a COMMITTED audit row was LOST on failover (G-REL §316 zero-loss VIOLATED)"
fi
# (b) the specific just-before-kill row (the one the negative control loses).
LAST_PRESENT="$(psql_super_val "SELECT count(*) FROM ${DRILL_TABLE} WHERE seq = ${LAST_SEQ};" | tr -d '[:space:]')"
if [ "${LAST_PRESENT}" = "1" ]; then
  _pass "the last-before-kill committed row (seq=${LAST_SEQ}) is PRESENT on the promoted primary"
else
  _fail "the last-before-kill committed row (seq=${LAST_SEQ}) is MISSING on the promoted primary — committed-audit LOSS (G-REL §316 VIOLATED)"
fi
# (c) NO seq gap — the append-order key is contiguous 1..max (ADR-0038 §3). A gap
#     means a mid-chain committed row vanished. count(*) must equal max(seq).
GAP_ROWS="$(psql_super_val "
  SELECT count(*) FROM (
    SELECT generate_series(1, (SELECT max(seq) FROM ${DRILL_TABLE})) AS s
  ) g
  LEFT JOIN ${DRILL_TABLE} t ON t.seq = g.s
  WHERE t.seq IS NULL;
" | tr -d '[:space:]')"
if [ "${GAP_ROWS}" = "0" ]; then
  _pass "NO seq gap on the promoted primary (append-order 1..max contiguous, ADR-0038 §3)"
else
  _fail "${GAP_ROWS} seq GAP(s) on the promoted primary — a committed audit row is missing mid-chain (G-REL §316 VIOLATED)"
fi
# (d) HASH-CHAIN VALID — every row's prev_hash links its predecessor's entry_hash
#     (ordered by seq), the first row chains from GENESIS. This is the ADR-0038 §1
#     structural invariant; a broken/missing link is a chain break. Counts the
#     rows whose prev_hash does NOT equal the predecessor's entry_hash (0 = valid).
CHAIN_BREAKS="$(psql_super_val "
  WITH ordered AS (
    SELECT seq, prev_hash, entry_hash,
           lag(entry_hash) OVER (ORDER BY seq) AS want_prev
    FROM ${DRILL_TABLE}
  )
  SELECT count(*) FROM ordered
  WHERE prev_hash <> coalesce(want_prev, decode(repeat('00', 32), 'hex'));
" | tr -d '[:space:]')"
if [ "${CHAIN_BREAKS}" = "0" ]; then
  _pass "hash-chain VALID on the promoted primary (every prev_hash links the predecessor entry_hash; genesis first — ADR-0038 §1)"
else
  _fail "${CHAIN_BREAKS} hash-chain BREAK(s) on the promoted primary — the surviving audit chain is not intact (ADR-0038 §1 / G-REL §316 VIOLATED)"
fi

echo "== W4-T3 failover drill complete: $(assert_failures) failure(s) =="
echo "   scale: CNPG instances=3 (quorum minimum), seed_rows=${SEED_ROWS}, RTO budget=${RTO_BUDGET_S}s from kill."
echo "   certified-scale failover + 30-day soak: NAMED deferred-accepted -> GA (ADR-0047 §4)."
