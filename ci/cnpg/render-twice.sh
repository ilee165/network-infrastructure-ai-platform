#!/usr/bin/env bash
# L4 render-twice idempotency guard for the CloudNativePG superuser/replication
# credential Secret (W1-T1, ADR-0042 §1 / P1-W4-LESSONS L4).
#
# THE TRAP (L4): a `helm upgrade` that REGENERATES the CNPG superuser or app/
# replication PASSWORD would no longer match the credential CNPG baked into PGDATA
# at first bootstrap and would SEVER every live DB connection. The dev/CI fallback
# in templates/cloudnativepg-secret.yaml therefore uses the `lookup` REUSE-OR-
# GENERATE pattern: on upgrade the installed Secret's password is REUSED; only a
# first install / fresh CI render generates. Production (external-secrets) owns the
# credential and never regenerates on a chart upgrade either.
#
# This script is the LOCAL guard (no cluster needed — `helm template` only). It
# proves three things that together close the L4 trap:
#   1. The reuse-or-generate branch is WIRED and keyed on `lookup` of the prior
#      Secret (so a real upgrade REUSES, never regenerates) — a structural grep.
#   2. Two FRESH renders generate DISTINCT passwords (no cluster => lookup empty =>
#      both generate), confirming generation actually happens — so the reuse
#      branch is the load-bearing upgrade-stability guard, not decorative.
#   3. The REUSE branch is STABLE + verbatim: fed a FIXED prior, two renders yield
#      a BYTE-IDENTICAL password that EQUALS the injected prior (a `helm upgrade`
#      reusing the installed Secret never changes the password). `helm template`'s
#      real `lookup` cannot be primed without an API server, so this asserts the
#      reuse via the ci/cnpg/reuse-fixture chart, which embeds the IDENTICAL Sprig
#      reuse idiom (`index $prior.data <key> | b64dec`) the production template runs.
#
# The LIVE reuse-across-upgrade path on a REAL cluster (production `lookup` reading
# an actually-installed Secret) requires a cluster and is exercised by the W4 kind
# harness — named-deferred (this host has no kind). Check (3) asserts the reuse-
# branch LOGIC is stable here and now; the kind run confirms the live `lookup` wiring.
#
# L5: `set -o pipefail` + `test -s` on every render so a masked helm exit / empty
# render reads as a failure, not a false-green.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
CHART_DIR="${REPO_ROOT}/deploy/kubernetes/netops"
TEMPLATE="${CHART_DIR}/templates/cloudnativepg-secret.yaml"
FIXTURE_DIR="${HERE}/reuse-fixture"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

fail=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fail=$((fail + 1)); }

PY="$(command -v python3 || command -v python)"
if [ -z "${PY}" ]; then
  echo "::error::no python3/python on PATH for the render-twice extractor" >&2
  exit 2
fi
extract() { "${PY}" "${HERE}/extract_stringdata.py" "$1" "$2" "$3"; }

# --- 1. the reuse-or-generate branch is wired (the upgrade-stability guard) ----
if grep -Eq 'lookup "v1" "Secret"' "${TEMPLATE}"; then
  ok "CNPG secret template looks up the prior Secret (reuse-on-upgrade path present, L4)"
else
  bad "CNPG secret template must \`lookup\` the prior Secret to REUSE the password on upgrade (L4 regen-on-upgrade trap)"
fi
if grep -Eq 'randAlphaNum' "${TEMPLATE}"; then
  ok "CNPG secret template generates a password on first install / fresh CI render"
else
  bad "CNPG secret template must generate the password (randAlphaNum) when no prior Secret exists"
fi
if grep -Eq 'hasKey \$superData|hasKey \$appData|index \$superData|index \$appData' "${TEMPLATE}"; then
  ok "CNPG secret template REUSES the installed password (index/hasKey on the prior Secret data, L4)"
else
  bad "CNPG secret template must reuse the installed Secret's password on upgrade (L4)"
fi

# --- 2. two FRESH renders generate DISTINCT passwords --------------------------
render_fresh() { # <out>
  set -o pipefail
  helm template netops "${CHART_DIR}" \
    --namespace netops --kube-version 1.29.0 \
    --set cloudNativePg.enabled=true \
    --set services.postgres.enabled=false \
    --set mtls.postgres.enabled=false \
    | tr -d '\r' > "$1"
  test -s "$1"
}
render_fresh "${WORK}/a.yaml"
render_fresh "${WORK}/b.yaml"

super_a="$(extract "${WORK}/a.yaml" netops-cnpg-superuser password)"
super_b="$(extract "${WORK}/b.yaml" netops-cnpg-superuser password)"
app_a="$(extract "${WORK}/a.yaml" netops-cnpg-app password)"
app_b="$(extract "${WORK}/b.yaml" netops-cnpg-app password)"

if [ -n "${super_a}" ] && [ -n "${app_a}" ]; then
  ok "fresh render produced non-empty superuser + app passwords"
else
  bad "fresh render produced an EMPTY superuser/app password (generation broken)"
fi
if [ "${super_a}" != "${super_b}" ] && [ "${app_a}" != "${app_b}" ]; then
  ok "two fresh renders generate DISTINCT passwords (so the lookup-reuse branch is the load-bearing upgrade-stability guard, L4)"
else
  bad "two fresh renders produced an IDENTICAL password — generation is a no-op; the L4 reuse guard cannot be load-bearing"
fi

# --- 3. the REUSE branch is STABLE + verbatim (the L4 upgrade-stability bite) ---
# Mint a deterministic prior (any fixed value), inject it base64 into the fixture,
# render twice; the password MUST be byte-identical AND equal the injected prior.
PRIOR_SUPER="cnpg-super-prior-pw-fixed-0001"
PRIOR_APP="cnpg-app-prior-pw-fixed-0002"
PRIOR_SUPER_B64="$(printf '%s' "${PRIOR_SUPER}" | base64 | tr -d '\n')"
PRIOR_APP_B64="$(printf '%s' "${PRIOR_APP}" | base64 | tr -d '\n')"

render_reuse() { # <out>
  set -o pipefail
  helm template fx "${FIXTURE_DIR}" --namespace netops --kube-version 1.29.0 \
    --set prior.superuserPasswordB64="${PRIOR_SUPER_B64}" \
    --set prior.appPasswordB64="${PRIOR_APP_B64}" \
    | tr -d '\r' > "$1"
  test -s "$1"
}
render_reuse "${WORK}/reuse_a.yaml"
render_reuse "${WORK}/reuse_b.yaml"

ra_super="$(extract "${WORK}/reuse_a.yaml" netops-cnpg-superuser password)"
rb_super="$(extract "${WORK}/reuse_b.yaml" netops-cnpg-superuser password)"
ra_app="$(extract "${WORK}/reuse_a.yaml" netops-cnpg-app password)"
rb_app="$(extract "${WORK}/reuse_b.yaml" netops-cnpg-app password)"

if [ "${ra_super}" = "${rb_super}" ] && [ "${ra_app}" = "${rb_app}" ]; then
  ok "reuse branch is STABLE across renders — render-twice idempotency holds (L4)"
else
  bad "reuse branch is UNSTABLE: a password differs across renders (an upgrade would re-issue it and sever auth, L4)"
fi
if [ "${ra_super}" = "${PRIOR_SUPER}" ] && [ "${ra_app}" = "${PRIOR_APP}" ]; then
  ok "reuse branch returns the prior password verbatim (no regen on upgrade, L4)"
else
  bad "reuse branch did NOT return the injected prior password — it regenerated (the L4 trap)"
fi

echo "== CNPG render-twice summary: ${fail} failure(s) =="
if [ "${fail}" -ne 0 ]; then
  echo "::error::CNPG render-twice L4 guard found ${fail} violation(s)" >&2
  exit 1
fi
echo "CNPG render-twice L4 guard: all invariants hold."
