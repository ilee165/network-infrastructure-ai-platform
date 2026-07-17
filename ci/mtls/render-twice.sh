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
# proves three things that together close the L4 trap:
#   1. The reuse-or-generate branch is WIRED and keyed on `lookup` of the prior
#      Secret (so a real upgrade REUSES, never regenerates) — a structural grep.
#   2. A fresh render produces INTERNALLY-CONSISTENT material (the dev CA signs
#      both the server and client leaf), so the generated pair is actually usable
#      AND two fresh renders DIFFER — confirming generation happens (the hazard
#      the reuse branch guards), so the guard is load-bearing, not decorative.
#   3. The REUSE branch is STABLE: fed a prior Secret, two renders yield
#      BYTE-IDENTICAL cert material (the actual L4 upgrade-stability invariant —
#      the spec's "render-twice stable" bite). `helm template`'s real `lookup`
#      cannot be primed without an API server, so this asserts the reuse via the
#      ci/mtls/reuse-fixture chart, which embeds the IDENTICAL Sprig reuse idiom
#      (`index $prior.data "tls.crt" | b64dec`) the production template runs on
#      upgrade — the prior injected through values instead of read by lookup.
#
# The LIVE reuse-across-upgrade path on a REAL cluster (production `lookup` reading
# an actually-installed Secret) requires a cluster and is exercised by the W4-T3
# kind harness — named-deferred to the W5 release auditor (this host has no
# cluster). Check (3) asserts the reuse-branch LOGIC is stable here and now; the
# kind run confirms the live `lookup` wiring feeds that logic. See the W4-T4 report.
#
# L5: `set -o pipefail` + the shared non-empty assertion on every render so a
# masked helm exit / empty render reads as a failure, not a false-green.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/render-twice-common.sh
source "${HERE}/../lib/render-twice-common.sh"
render_twice_init

TEMPLATE="${CHART_DIR}/templates/mtls-postgres.yaml"

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
  # L5: pipefail so a helm-template failure is not masked by `tr`; the shared
  # assertion guards an empty render. Dev fallback path (certManager off) so the chart GENERATES
  # the material this script inspects (the cert-manager path emits CR specs only).
  set -o pipefail
  helm template netops "${CHART_DIR}" \
    --namespace netops --kube-version 1.29.0 \
    --set mtls.postgres.enabled=true \
    --set mtls.postgres.certManager.enabled=false \
    | tr -d '\r' > "$1"
  render_twice_require_nonempty "$1"
}

# Extract a base64 PEM value for a given Secret name + data key from a render.
extract() { # <render-file> <secret-name> <data-key>  -> writes PEM to stdout
  extract_rendered_secret data "$1" "$2" "$3"
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

# --- 3. the REUSE branch is STABLE across renders (the L4 upgrade-stability bite) -
# Feed a FIXED prior Secret into the reuse idiom and render twice; the material
# MUST be byte-identical (a `helm upgrade` reusing the installed Secret never
# changes the cert). `helm template`'s real `lookup` cannot be primed here, so the
# reuse-fixture chart injects the prior via values while running the IDENTICAL
# Sprig reuse calls as templates/mtls-postgres.yaml.
#
# The prior triple is minted by ONE generate-branch fixture render (empty prior =>
# genCA/genSignedCert, the same path a fresh install takes), then extracted and
# fed BACK as the injected prior. This keeps the prior self-consistent and avoids
# any host openssl-subj quirks (MSYS path-mangling on Windows) — pure helm.
FIXTURE_DIR="${HERE}/reuse-fixture"
PRIOR="${WORK}/prior"; mkdir -p "${PRIOR}"

# 3a. Mint the prior via the GENERATE branch (empty prior.* defaults).
set -o pipefail
helm template fx "${FIXTURE_DIR}" --namespace netops --kube-version 1.29.0 \
  | tr -d '\r' > "${WORK}/seed.yaml"
render_twice_require_nonempty "${WORK}/seed.yaml"
extract "${WORK}/seed.yaml" netops-db-ca-tls           ca.crt  > "${PRIOR}/ca.crt"
extract "${WORK}/seed.yaml" netops-postgres-server-tls tls.crt > "${PRIOR}/srv.crt"
extract "${WORK}/seed.yaml" netops-postgres-server-tls tls.key > "${PRIOR}/srv.key"
extract "${WORK}/seed.yaml" netops-db-client-tls       tls.crt > "${PRIOR}/cli.crt"
extract "${WORK}/seed.yaml" netops-db-client-tls       tls.key > "${PRIOR}/cli.key"

render_reuse() { # <out>
  set -o pipefail
  helm template fx "${FIXTURE_DIR}" --namespace netops --kube-version 1.29.0 \
    --set-file prior.caCrt="${PRIOR}/ca.crt" \
    --set-file prior.srvCrt="${PRIOR}/srv.crt" \
    --set-file prior.srvKey="${PRIOR}/srv.key" \
    --set-file prior.cliCrt="${PRIOR}/cli.crt" \
    --set-file prior.cliKey="${PRIOR}/cli.key" \
    | tr -d '\r' > "$1"
  render_twice_require_nonempty "$1"
}

render_reuse "${WORK}/reuse_a.yaml"
render_reuse "${WORK}/reuse_b.yaml"

reuse_stable=1
for sec_key in "netops-db-ca-tls:ca.crt" \
               "netops-postgres-server-tls:tls.crt" \
               "netops-postgres-server-tls:tls.key" \
               "netops-db-client-tls:tls.crt" \
               "netops-db-client-tls:tls.key"; do
  sec="${sec_key%%:*}"; dk="${sec_key##*:}"
  va="${WORK}/ra_${sec}_${dk}"; vb="${WORK}/rb_${sec}_${dk}"
  extract "${WORK}/reuse_a.yaml" "${sec}" "${dk}" > "${va}"
  extract "${WORK}/reuse_b.yaml" "${sec}" "${dk}" > "${vb}"
  if ! cmp -s "${va}" "${vb}"; then
    bad "reuse branch is UNSTABLE: ${sec}/${dk} differs across renders (an upgrade would re-issue this cert and sever auth, L4)"
    reuse_stable=0
  fi
done
# The reuse output must equal the INJECTED prior verbatim (proves it REUSED, did
# not regenerate) — compare the server cert against the minted prior.
if cmp -s "${WORK}/ra_netops-postgres-server-tls_tls.crt" "${PRIOR}/srv.crt"; then
  ok "reuse branch returns the prior material verbatim (no regen on upgrade, L4)"
else
  bad "reuse branch did NOT return the injected prior server cert — it regenerated (the L4 trap)"
  reuse_stable=0
fi
if [ "${reuse_stable}" -eq 1 ]; then
  ok "reuse branch is STABLE across renders — render-twice idempotency holds (L4)"
fi

# --- 4. FAIL CLOSED on an INCOMPLETE prior (M4, PR#76) -------------------------
# A half-set prior Secret (e.g. the server triple present but the CLIENT key
# missing/empty) must NOT take the reuse branch and emit EMPTY client cert/key
# material (fail-open) — it must REGENERATE the whole triple consistently. Feed the
# fixture a prior with the client key BLANKED and assert the rendered client cert is
# (a) NON-EMPTY and (b) a valid regenerated PEM, not the empty injected member.
render_partial_reuse() { # <out>
  set -o pipefail
  helm template fx "${FIXTURE_DIR}" --namespace netops --kube-version 1.29.0 \
    --set-file prior.caCrt="${PRIOR}/ca.crt" \
    --set-file prior.srvCrt="${PRIOR}/srv.crt" \
    --set-file prior.srvKey="${PRIOR}/srv.key" \
    --set-file prior.cliCrt="${PRIOR}/cli.crt" \
    --set prior.cliKey="" \
    | tr -d '\r' > "$1"
  render_twice_require_nonempty "$1"
}
render_partial_reuse "${WORK}/partial.yaml"
partial_cli_crt="${WORK}/partial_cli.crt"
partial_cli_key="${WORK}/partial_cli.key"
extract "${WORK}/partial.yaml" netops-db-client-tls tls.crt > "${partial_cli_crt}"
extract "${WORK}/partial.yaml" netops-db-client-tls tls.key > "${partial_cli_key}"
if [ -s "${partial_cli_crt}" ] && [ -s "${partial_cli_key}" ] \
   && openssl x509 -in "${partial_cli_crt}" -noout >/dev/null 2>&1; then
  ok "incomplete prior REGENERATES non-empty client cert/key (fail closed, never empty — M4)"
else
  bad "incomplete prior emitted EMPTY/invalid client cert material (fail-open — M4 regression)"
fi

render_twice_finish "mTLS render-twice" "mTLS render-twice L4 guard"
