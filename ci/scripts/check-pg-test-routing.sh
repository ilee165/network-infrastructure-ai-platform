#!/usr/bin/env bash
#
# PG-test routing heuristic (audit ARCH_DEBT #2).
#
# The fast unit suite runs on SQLite and is blind to PostgreSQL-only semantics
# (NULLS-FIRST ordering, partial/partitioned indexes, advisory locks, `SET
# LOCAL`, write-locking). Those must be exercised by the Postgres-backed layer
# under `backend/tests/pg/` (the blocking `pg-integration` CI job). This check
# makes an omission visible at review time: if a diff ADDS a PG-specific SQL /
# semantic marker to non-test backend code WITHOUT touching `backend/tests/pg/`,
# it fails and points the author at the routing rule (backend/tests/pg/README.md).
#
# It is a heuristic, not a proof — deliberately cheap (a diff grep, no DB). It
# can be silenced for a legitimately-covered change by including any edit under
# `backend/tests/pg/` in the same PR (the normal way to satisfy the rule), or by
# setting PG_ROUTING_ALLOW=1 for a reviewed exception.
#
# Usage: check-pg-test-routing.sh [BASE_REF]
#   BASE_REF defaults to origin/main. The compared range is
#   merge-base(BASE_REF, HEAD)..HEAD, so only what this branch adds is judged.

set -euo pipefail

BASE_REF="${1:-origin/main}"

# Paths whose PG-semantic changes must be mirrored by a tests/pg/ change.
SCAN_PATHS=("backend/app" "backend/alembic/versions")
PG_TEST_DIR="backend/tests/pg"

# PG-specific markers (audit ARCH_DEBT #2: postgresql_where, SET LOCAL, advisory
# locks, partition DDL) plus a few adjacent Postgres-only semantics.
MARKERS='postgresql_where|postgresql_using|SET[[:space:]]+LOCAL|pg_advisory[_a-z]*lock|PARTITION[[:space:]]+(BY|OF)|ATTACH[[:space:]]+PARTITION|NULLS[[:space:]]+(FIRST|LAST)|synchronous_commit'

if ! MERGE_BASE="$(git merge-base "$BASE_REF" HEAD 2>/dev/null)"; then
  # No shared history (shallow/first-commit): compare against the empty tree so
  # the check still runs rather than silently passing.
  MERGE_BASE="$(git hash-object -t tree /dev/null)"
fi

# Added lines (drop the +++ file header) touching the scanned non-test paths.
added_hits="$(
  git diff "$MERGE_BASE"..HEAD -- "${SCAN_PATHS[@]}" \
    | grep -E '^\+' | grep -Ev '^\+\+\+' \
    | grep -EnI "$MARKERS" || true
)"

if [[ -z "$added_hits" ]]; then
  echo "pg-test-routing: no PG-semantic markers added to ${SCAN_PATHS[*]} — OK"
  exit 0
fi

# A tests/pg/ change in the same range satisfies the rule.
if git diff --name-only "$MERGE_BASE"..HEAD -- "$PG_TEST_DIR" | grep -q .; then
  echo "pg-test-routing: PG-semantic markers added AND ${PG_TEST_DIR}/ changed — OK"
  exit 0
fi

if [[ "${PG_ROUTING_ALLOW:-0}" == "1" ]]; then
  echo "pg-test-routing: markers added without ${PG_TEST_DIR}/ change, but PG_ROUTING_ALLOW=1 — allowed (reviewed exception)"
  exit 0
fi

echo "::error::pg-test-routing: PG-specific SQL/semantics were added to backend code with no matching ${PG_TEST_DIR}/ test change."
echo
echo "Markers found in added lines:"
echo "$added_hits" | sed 's/^/  /'
echo
echo "PG-only semantics are invisible to the SQLite unit suite. Add a Postgres-backed"
echo "test under ${PG_TEST_DIR}/ (run by the blocking pg-integration job). See"
echo "${PG_TEST_DIR}/README.md. For a genuinely-covered change, set PG_ROUTING_ALLOW=1."
exit 1
