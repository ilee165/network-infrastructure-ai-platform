#!/usr/bin/env bash
# W4-T4 mTLS handshake assertion (ADR-0039 §6) — plugged into the W4-T3 runner.
#
# THE BITE (refusal proven, not just a working TLS path): against the chart's
# Postgres over the in-cluster api/worker↔postgres link, this check proves
#   1. a VALID-cert client (sslmode=verify-full, the mounted client cert)
#      HANDSHAKES + authenticates;
#   2. a PLAINTEXT client (sslmode=disable) is REFUSED — the pg_hba has only a
#      `hostssl … clientcert=verify-full` rule, no plaintext `host` line;
#   3. a WRONG-CA client (a throwaway cert minted here) is REFUSED — the server
#      verifies the client cert against its trusted CA only.
# Cases 2+3 are the deterministic enforcement bite (ADR-0039 §3/§6).
#
# Runs ONLY after the harness applied the chart AND the CNI self-test passed
# (kind-harness.sh guarantees both). It sources ../lib.sh and signals failure via
# assert_handshake_* (the runner counts a non-zero assert_failures as a failed
# check). L3: every value the in-pod shell needs is a POSITIONAL arg to `sh -c`,
# never $(VAR) in an exec argv. L5: pipefail is on (the runner sets it).
#
# REQUIRES the chart rendered with mtls.postgres.enabled=true. The harness applies
# the default chart (mtls off) today, so this check SKIPS (loudly, never silently
# false-green) unless the mTLS objects are present — the W5 promotion enables mTLS
# in the harness apply and flips this to an enforcing assertion (see the W4-T4
# report: live kind validation is CI-only / deferred-accepted-named).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
. "${HERE}/../lib.sh"

NS="${CHART_NS:-netops}"
PROBE_POD="mtls-postgres-probe"
PG_HOST="${PG_HOST:-netops-postgres}"
PG_PORT="${PG_PORT:-5432}"
PG_DB="${PG_DB:-netops}"
PG_USER="${PG_USER:-netops}"
PROBE_MANIFEST="${HERE}/mtls-postgres-probe.yaml"

echo "== W4-T4 mTLS handshake assertion (ns=${NS}, host=${PG_HOST}) =="

# --- precondition: the mTLS objects must be present, else SKIP loudly ----------
# The chart only renders the client Secret + pg_hba when mtls.postgres.enabled.
# If they are absent the harness applied an mTLS-off chart; assert nothing rather
# than read a missing control as a pass (a silent no-op is a false-green — the
# runner also fails an empty log, so we always emit output).
if ! kubectl -n "${NS}" get secret netops-db-client-tls >/dev/null 2>&1; then
  echo "SKIP: netops-db-client-tls Secret absent — chart applied with mTLS OFF."
  echo "      Enable mtls.postgres.enabled in the harness apply to assert the"
  echo "      handshake/refusal bite (W4-T4 live validation is W5-promoted)."
  exit 0
fi

# --- DB password (by-reference; never printed) --------------------------------
# Read from the platform Secret the chart provisions; passed to psql via PGPASSWORD
# env inside the pod (set with `kubectl exec --env`-free `sh -c` positional arg),
# never echoed. --redact-style discipline: we never `echo` the value.
PGPASSWORD_VALUE="$(kubectl -n "${NS}" get secret netops-dev-secrets \
  -o jsonpath='{.data.postgres-password}' 2>/dev/null | base64 -d || true)"
if [ -z "${PGPASSWORD_VALUE}" ]; then
  # An existingSecret deployment uses a different Secret name; the harness/dev
  # path uses the chart-generated one. Without it we cannot authenticate, so we
  # fail loudly rather than silently skip the authenticated cases.
  echo "::error::could not read the postgres password from netops-dev-secrets — cannot run the authenticated handshake cases" >&2
  exit 1
fi

# --- bring up the probe pod ----------------------------------------------------
cleanup() { kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=false || true; }
# N1: register with lib.sh's assert-exit trap instead of `trap cleanup EXIT` — a
# bare EXIT trap here would CLOBBER lib.sh's _assert_exit_trap (bash keeps only the
# last EXIT trap), so a recorded assert-fail with an rc=0 body would read
# false-green. register_cleanup composes teardown WITH the assert-fail bite.
register_cleanup cleanup
kubectl -n "${NS}" delete pod "${PROBE_POD}" --ignore-not-found --wait=true || true
kubectl -n "${NS}" apply -f "${PROBE_MANIFEST}"
kubectl -n "${NS}" wait --for=condition=Ready "pod/${PROBE_POD}" --timeout=120s

# Copy the mounted client key to a 0600 path the probe user owns (libpq refuses a
# group/world-readable or non-owned key file). L3: no $(VAR) in the exec argv.
kubectl -n "${NS}" exec "${PROBE_POD}" -- sh -c '
  set -e
  mkdir -p /tmp/cli
  cp /certs/tls.crt /tmp/cli/client.crt
  cp /certs/tls.key /tmp/cli/client.key
  cp /certs/ca.crt  /tmp/cli/ca.crt
  chmod 0600 /tmp/cli/client.key
'

# A throwaway WRONG CA + client cert (untrusted by the server) for case 3. Minted
# inside the pod with openssl (present in the pgvector image). L3: positional args.
kubectl -n "${NS}" exec "${PROBE_POD}" -- sh -c '
  set -e
  mkdir -p /tmp/bad
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout /tmp/bad/client.key -out /tmp/bad/client.crt \
    -subj "/CN=$1" >/dev/null 2>&1
  chmod 0600 /tmp/bad/client.key
' _ "${PG_USER}"

# N11: the DB password is fed to the in-pod shell over STDIN (`kubectl exec -i`,
# read into PGPASSWORD), NEVER as a `sh -c` positional argv arg — an argv arg is
# visible in the pod's process listing (`ps` / /proc/<pid>/cmdline). The in-pod
# shell `read`s the single line, exports PGPASSWORD, then execs psql; the value
# never appears in any process's argv and is never echoed. Connection params + SSL
# file paths remain positional args (L3 — they are not secret).
#
# psql runner inside the pod.
# Args: $1 host $2 port $3 db $4 user $5 sslmode $6 sslcert $7 sslkey $8 sslroot
psql_probe() {
  local sslmode="$1" certdir="$2"
  printf '%s' "${PGPASSWORD_VALUE}" | kubectl -n "${NS}" exec -i "${PROBE_POD}" -- sh -c '
    IFS= read -r PGPASSWORD
    export PGPASSWORD
    exec psql \
      "host=$1 port=$2 dbname=$3 user=$4 sslmode=$5 sslcert=$6 sslkey=$7 sslrootcert=$8 connect_timeout=10" \
      -tAc "SELECT 1" >/dev/null 2>&1
  ' _ "${PG_HOST}" "${PG_PORT}" "${PG_DB}" "${PG_USER}" \
      "${sslmode}" "${certdir}/client.crt" "${certdir}/client.key" "${certdir}/ca.crt"
}

plaintext_probe() {
  # sslmode=disable — no cert files; the server must refuse (no plaintext line).
  # Password via STDIN (N11), not argv.
  printf '%s' "${PGPASSWORD_VALUE}" | kubectl -n "${NS}" exec -i "${PROBE_POD}" -- sh -c '
    IFS= read -r PGPASSWORD
    export PGPASSWORD
    exec psql \
      "host=$1 port=$2 dbname=$3 user=$4 sslmode=disable connect_timeout=10" \
      -tAc "SELECT 1" >/dev/null 2>&1
  ' _ "${PG_HOST}" "${PG_PORT}" "${PG_DB}" "${PG_USER}"
}

wrong_ca_probe() {
  # Present the throwaway (untrusted) client cert but verify the server with the
  # REAL CA, so only the CLIENT-side trust is wrong — the server rejects it.
  # Reuses the same positional-arg form as psql_probe (L3), pointing sslcert/key
  # at /tmp/bad and sslrootcert at the real /tmp/cli/ca.crt. Password via STDIN (N11).
  printf '%s' "${PGPASSWORD_VALUE}" | kubectl -n "${NS}" exec -i "${PROBE_POD}" -- sh -c '
    IFS= read -r PGPASSWORD
    export PGPASSWORD
    exec psql \
      "host=$1 port=$2 dbname=$3 user=$4 sslmode=verify-full sslcert=/tmp/bad/client.crt sslkey=/tmp/bad/client.key sslrootcert=/tmp/cli/ca.crt connect_timeout=10" \
      -tAc "SELECT 1" >/dev/null 2>&1
  ' _ "${PG_HOST}" "${PG_PORT}" "${PG_DB}" "${PG_USER}"
}

# --- 1. valid-cert client must HANDSHAKE (verify-full) ------------------------
assert_handshake_ok "valid client cert + verify-full" -- psql_probe verify-full /tmp/cli

# --- 2. plaintext client must be REFUSED -------------------------------------
assert_handshake_refused "plaintext (sslmode=disable) client" -- plaintext_probe

# --- 3. wrong-CA client must be REFUSED --------------------------------------
assert_handshake_refused "wrong-CA client cert" -- wrong_ca_probe

echo "== mTLS handshake assertion complete: $(assert_failures) failure(s) =="
