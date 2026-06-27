#!/usr/bin/env bash
# External-Postgres + mTLS fail-fast guard (PR#76 round-2 #25).
#
# Proves the chart REFUSES to silently produce a broken deploy when DB-link mTLS
# is on but the Postgres is EXTERNAL and the operator has NOT attested the
# external server's mTLS is provisioned out-of-band. Three render combinations:
#   (A) mtls-on + services.postgres.enabled=false + NO external ack -> helm FAILS
#   (B) mtls-on + services.postgres.enabled=false + external.enabled=true -> OK,
#       and NO in-chart pg_hba ConfigMap renders (no in-chart server to mount it)
#   (C) mtls-on + in-chart Postgres (default) -> OK and the pg_hba ConfigMap renders
# A regression in either direction (silent broken external deploy, or a false
# fail-fast on the supported in-chart path) fails this script.
#
# Run:  bash ci/mtls/external-pg-failfast.sh
# CI:   the `infra` job runs this (needs only helm).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
CHART="${REPO}/deploy/kubernetes/netops"
KUBEV="${KUBE_VERSION:-1.30.0}"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
fail=0

# render <out-file> <args...> -> exit status of helm; stdout+stderr captured to file.
# Rendering to a FILE (not a shell var) keeps large outputs out of command
# substitution — robust on hosts whose shell struggles to buffer a ~230KB capture.
render() {
  local out="$1"; shift
  helm template netops "${CHART}" --kube-version "${KUBEV}" "$@" >"${out}" 2>&1
}

echo "== external-Postgres + mTLS fail-fast guard =="

# (A) external pg + mtls-on + NO ack -> helm MUST fail (non-zero) with the message.
echo "-- (A) mtls-on + external pg + NO ack -> EXPECT helm FAIL --"
if render "${WORK}/a.yaml" --set mtls.postgres.enabled=true --set services.postgres.enabled=false; then
  echo "FAIL: render SUCCEEDED for external pg + mtls-on without external.enabled — a broken-deploy combination was NOT refused" >&2
  fail=1
elif grep -q 'external Postgres' "${WORK}/a.yaml"; then
  echo "PASS: render was REFUSED (fail-fast) for external pg + mtls-on without attestation"
else
  echo "FAIL: render failed but NOT with the external-Postgres fail-fast message (unexpected error):" >&2
  tail -3 "${WORK}/a.yaml" >&2
  fail=1
fi

# (B) external pg + mtls-on + external.enabled=true -> renders, NO pg_hba ConfigMap.
echo "-- (B) mtls-on + external pg + external.enabled=true -> EXPECT render OK, no in-chart pg_hba --"
if render "${WORK}/b.yaml" --set mtls.postgres.enabled=true --set services.postgres.enabled=false --set mtls.postgres.external.enabled=true; then
  if grep -q 'postgres-tls-config' "${WORK}/b.yaml"; then
    echo "FAIL: an in-chart pg_hba ConfigMap rendered for an EXTERNAL Postgres (nothing mounts it; misleading)" >&2
    fail=1
  else
    echo "PASS: render OK and NO in-chart pg_hba ConfigMap (external server's pg_hba is out-of-band)"
  fi
else
  echo "FAIL: render was REFUSED even though external.enabled=true attests external mTLS:" >&2
  tail -3 "${WORK}/b.yaml" >&2
  fail=1
fi

# (C) in-chart Postgres (default) + mtls-on -> renders, pg_hba ConfigMap present.
echo "-- (C) mtls-on + in-chart pg (default) -> EXPECT render OK + pg_hba ConfigMap --"
if render "${WORK}/c.yaml" --set mtls.postgres.enabled=true; then
  if grep -q 'postgres-tls-config' "${WORK}/c.yaml"; then
    echo "PASS: in-chart pg render OK and the pg_hba ConfigMap is present"
  else
    echo "FAIL: in-chart pg render is missing the pg_hba ConfigMap (the mTLS refusal control)" >&2
    fail=1
  fi
else
  echo "FAIL: the supported in-chart pg + mtls-on path was REFUSED (false fail-fast):" >&2
  tail -3 "${WORK}/c.yaml" >&2
  fail=1
fi

if [ "${fail}" -ne 0 ]; then
  echo "::error::external-Postgres + mTLS fail-fast guard FAILED" >&2
  exit 1
fi
echo "external-Postgres + mTLS fail-fast guard: all combinations correct."
