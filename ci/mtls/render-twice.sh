#!/usr/bin/env bash
# L4 render-twice idempotency guard for the api/worker↔postgres mTLS cert
# material (W4-T4, ADR-0039 §5 / P1-W4-LESSONS L4).
#
# THE TRAP (L4): a `helm upgrade` that REGENERATES the DB cert material would
# re-issue every cert and SEVER every live DB connection. The dev/CI fallback in
# templates/mtls-postgres.yaml therefore uses the `lookup` REUSE-OR-GENERATE
# pattern: on upgrade the installed Secret's material is REUSED; only a first
# install / fresh CI render generates. cert-manager (the production path) owns
# rotation and never regenerates on a chart upgrade either.
#
# This script is the LOCAL guard (no cluster needed — `helm template` only). It
# proves two things that together close the L4 trap:
#   1. The reuse-or-generate branch is WIRED and keyed on `lookup` of the prior
#      Secret (so a real upgrade REUSES, never regenerates) — a structural grep.
#   2. A fresh render produces INTERNALLY-CONSISTENT material (the dev CA signs
#      both the server and client leaf), so the generated pair is actually usable
#      AND two fresh renders DIFFER — confirming generation happens (the hazard
#      the reuse branch guards), so the guard is load-bearing, not decorative.
#
# The LIVE reuse-across-upgrade path (lookup reading an installed Secret) requires
# a cluster and is exercised in CI / by the W4-T3 kind harness — named-deferred to
# the W5 release auditor (this host has no cluster). See the W4-T4 report.
#
# L5: `set -o pipefail` + `test -s` on every render so a masked helm exit / empty
# render reads as a failure, not a false-green.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
CHART_DIR="${REPO_ROOT}/deploy/kubernetes/netops"
TEMPLATE="${CHART_DIR}/templates/mtls-postgres.yaml"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fail=$((fail + 1)); }

# --- 1. the reuse-or-generate branch is wired (the upgrade-stability guard) ----
# A regex grep on the template: the dev fallback MUST `lookup` the prior Secret
# and REUSE its tls.crt when present, only generating (genCA/genSignedCert) in the
# else branch. Missing either half re-opens the L4 regen-on-upgrade trap.
if grep -Eq 'lookup "v1" "Secret"' "${TEMPLATE}"; then
  ok "mTLS template looks up the prior Secret (reuse-on-upgrade path present, L4)"
else
  bad "mTLS template must \`lookup\` the prior Secret to REUSE cert material on upgrade (L4 regen-on-upgrade trap)"
fi
if grep -Eq 'genCA|genSignedCert' "${TEMPLATE}"; then
  ok "mTLS template generates material on first install / fresh CI render"
else
  bad "mTLS template must generate cert material (genCA/genSignedCert) when no prior Secret exists"
fi
if grep -Eq 'hasKey \$srvPrior\.data|index \$srvPrior\.data' "${TEMPLATE}"; then
  ok "mTLS template REUSES the installed material (index/hasKey on the prior Secret data, L4)"
else
  bad "mTLS template must reuse the installed Secret's tls.crt/tls.key on upgrade (L4)"
fi

# --- 2. a fresh render produces internally-consistent, usable material ---------
render() {
  # L5: pipefail so a helm-template failure is not masked by `tr`; test -s guards
  # an empty render. Dev fallback path (certManager off) so the chart GENERATES
  # the material this script inspects (the cert-manager path emits CR specs only).
  set -o pipefail
  helm template netops "${CHART_DIR}" \
    --namespace netops --kube-version 1.29.0 \
    --set mtls.postgres.enabled=true \
    --set mtls.postgres.certManager.enabled=false \
    | tr -d '\r' > "$1"
  test -s "$1"
}

# Python interpreter (CI ubuntu ships python3; a dev shell may only have python).
PY="$(command -v python3 || command -v python)"
if [ -z "${PY}" ]; then
  echo "::error::no python3/python on PATH for the render-twice extractor" >&2
  exit 2
fi

# Extract a base64 PEM value for a given Secret name + data key from a render.
extract() { # <render-file> <secret-name> <data-key>  -> writes PEM to stdout
  "${PY}" "${HERE}/extract_secret.py" "$1" "$2" "$3"
}

render "${WORK}/a.yaml"
render "${WORK}/b.yaml"

ca_a="${WORK}/ca_a.crt"; srv_a="${WORK}/srv_a.crt"; cli_a="${WORK}/cli_a.crt"
extract "${WORK}/a.yaml" netops-db-ca-tls          ca.crt  > "${ca_a}"
extract "${WORK}/a.yaml" netops-postgres-server-tls tls.crt > "${srv_a}"
extract "${WORK}/a.yaml" netops-db-client-tls       tls.crt > "${cli_a}"
ca_b="${WORK}/ca_b.crt"
extract "${WORK}/b.yaml" netops-db-ca-tls          ca.crt  > "${ca_b}"

for f in "${ca_a}" "${srv_a}" "${cli_a}"; do
  if [ -s "${f}" ] && openssl x509 -in "${f}" -noout >/dev/null 2>&1; then
    ok "rendered $(basename "${f}") is a valid PEM certificate"
  else
    bad "rendered $(basename "${f}") is not a valid PEM certificate"
  fi
done

# The dev CA must sign BOTH the server and client leaf (a self-consistent triple).
if openssl verify -CAfile "${ca_a}" -partial_chain "${srv_a}" >/dev/null 2>&1 \
   || openssl verify -CAfile "${ca_a}" "${srv_a}" >/dev/null 2>&1; then
  ok "dev CA signs the postgres SERVER cert (usable mTLS server identity)"
else
  bad "dev CA must sign the postgres SERVER cert (the verify chain is broken)"
fi
if openssl verify -CAfile "${ca_a}" -partial_chain "${cli_a}" >/dev/null 2>&1 \
   || openssl verify -CAfile "${ca_a}" "${cli_a}" >/dev/null 2>&1; then
  ok "dev CA signs the api/worker CLIENT cert (usable mTLS client identity)"
else
  bad "dev CA must sign the api/worker CLIENT cert (the verify chain is broken)"
fi

# Two FRESH renders (no cluster ⇒ lookup empty ⇒ both generate) MUST differ —
# this is exactly the regen the reuse branch guards on a real upgrade. If they
# were identical the generation would be a no-op and the L4 guard meaningless.
if cmp -s "${ca_a}" "${ca_b}"; then
  bad "two fresh renders produced an IDENTICAL CA — generation is a no-op; the L4 reuse guard cannot be load-bearing"
else
  ok "two fresh renders generate DISTINCT CAs (so the lookup-reuse branch is the load-bearing upgrade-stability guard, L4)"
fi

echo "== render-twice summary: ${fail} failure(s) =="
if [ "${fail}" -ne 0 ]; then
  echo "::error::mTLS render-twice L4 guard found ${fail} violation(s)" >&2
  exit 1
fi
echo "mTLS render-twice L4 guard: all invariants hold."
