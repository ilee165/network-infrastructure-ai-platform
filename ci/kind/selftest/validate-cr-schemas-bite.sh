#!/usr/bin/env bash
# CR-schema static guard — NEGATIVE-CONTROL BITE PROOF (P3 W4-T2 / audit-W2 T7, S1).
#
# Proves the CNPG/KEDA custom-resource strict field-validation guard
# (validate-cr-schemas.py, over the VENDORED pinned CRDs in ci/kind/crd-schemas/)
# actually BITES — i.e. it turns RED on the exact class the runAsNonRoot rot
# belonged to (an unknown field the live apply would reject), which kubeconform
# -skips and conftest never sees. No cluster needed; deterministic.
#
# Directions (plant -> red -> revert):
#   POSITIVE  the real HA render validates clean (exit 0) — the revert-to-green;
#   NEGATIVE  a planted unknown field under spec.postgresql makes the guard RED;
#   DRIFT     the vendored CRD versions must match the install-operators.sh pins
#             (a pin bump without a schema refresh BITES — never a silent stale pass).
#
# Blocking within its CI job (needs no cluster). Run locally:
#   bash ci/kind/selftest/validate-cr-schemas-bite.sh
#
# Requires: helm + python3 (+ PyYAML — installed below if absent) on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"
CHART_DIR="${REPO_ROOT}/deploy/kubernetes/netops"
OVERLAY="${CHART_DIR}/values-kind-ha.yaml"
VALIDATOR="${HERE}/validate-cr-schemas.py"
VERSIONS="${HERE}/../crd-schemas/VERSIONS"
INSTALL_OPS="${REPO_ROOT}/ci/kind/ha/install-operators.sh"

fail=0
ok()  { echo "PASS: $*"; }
bad() { echo "FAIL: $*" >&2; fail=1; }

echo "== CR-schema guard bite proof (S1 — CNPG/KEDA unknown-field class) =="

# PyYAML guard (present on the authoring host; the CI runner installs it here).
python3 -c "import yaml" 2>/dev/null || pip install --quiet --disable-pip-version-check pyyaml

# --- DRIFT: vendored CRD versions MUST match the operator pins -----------------
# shellcheck disable=SC1090
. "${VERSIONS}"
inst_cnpg="$(grep -E '^CNPG_VERSION=' "${INSTALL_OPS}" | head -1 | sed -E 's/.*:-([0-9.]+)\}.*/\1/')"
inst_keda="$(grep -E '^KEDA_VERSION=' "${INSTALL_OPS}" | head -1 | sed -E 's/.*:-([0-9.]+)\}.*/\1/')"
if [ "${inst_cnpg%.*}" = "${CNPG_RELEASE}" ]; then
  ok "vendored CNPG CRD release ${CNPG_RELEASE} matches install-operators pin ${inst_cnpg}"
else
  bad "vendored CNPG CRD release ${CNPG_RELEASE} != install-operators pin ${inst_cnpg} (refresh ci/kind/crd-schemas/ — README)"
fi
if [ "${inst_keda}" = "${KEDA}" ]; then
  ok "vendored KEDA CRD version ${KEDA} matches install-operators pin ${inst_keda}"
else
  bad "vendored KEDA CRD version ${KEDA} != install-operators pin ${inst_keda} (refresh ci/kind/crd-schemas/ — README)"
fi

# --- render the HA overlay (same as the harness / validate-ha-overlay) ---------
RENDERED="$(mktemp)"
set -o pipefail
if helm template netops "${CHART_DIR}" \
    --namespace netops --kube-version 1.29.0 \
    -f "${OVERLAY}" \
    --set mtls.postgres.enabled=true \
    --set mtls.postgres.certManager.enabled=false \
    | tr -d '\r' > "${RENDERED}" && [ -s "${RENDERED}" ]; then
  ok "HA overlay rendered (non-empty)"
else
  bad "HA overlay failed to render"; echo "== ${fail} failure(s) =="; exit 1
fi

# --- POSITIVE: the real render must validate CLEAN (exit 0) --------------------
if python3 "${VALIDATOR}" "${RENDERED}" >/tmp/cr_pos.out 2>&1; then
  ok "real HA render passes CR schema validation (0 unknown fields) — revert-to-green"
else
  bad "real HA render FAILED CR schema validation — a CR carries a field the live apply rejects"
  sed 's/^/    /' /tmp/cr_pos.out >&2
fi

# --- NEGATIVE CONTROL: plant an unknown field -> the guard MUST turn RED --------
PLANTED="$(mktemp)"
python3 - "${RENDERED}" "${PLANTED}" <<'PY'
import sys, yaml
docs = list(yaml.safe_load_all(open(sys.argv[1])))
planted = False
for d in docs:
    if isinstance(d, dict) and str(d.get("apiVersion","")).startswith("postgresql.cnpg.io/") \
            and d.get("kind") == "Cluster":
        d.setdefault("spec", {}).setdefault("postgresql", {})["__planted_t7_unknown__"] = True
        planted = True
        break
if not planted:
    sys.stderr.write("PLANT-ERROR: no CNPG Cluster in render to plant into\n"); sys.exit(3)
yaml.safe_dump_all([d for d in docs if d is not None], open(sys.argv[2], "w"))
PY
if python3 "${VALIDATOR}" "${PLANTED}" >/tmp/cr_neg.out 2>&1; then
  bad "planted unknown field spec.postgresql.__planted_t7_unknown__ did NOT turn the guard RED — the guard does not bite"
  sed 's/^/    /' /tmp/cr_neg.out >&2
else
  if grep -q "__planted_t7_unknown__" /tmp/cr_neg.out; then
    ok "planted unknown field turns the guard RED, naming the exact field (bite confirmed)"
  else
    bad "guard returned non-zero on the plant but did NOT name the planted field — wrong reason"
    sed 's/^/    /' /tmp/cr_neg.out >&2
  fi
fi

rm -f "${RENDERED}" "${PLANTED}"
echo "== CR-schema guard bite proof: ${fail} failure(s) =="
if [ "${fail}" -ne 0 ]; then
  echo "::error::CR-schema guard bite proof FAILED (guard missing, not biting, or CRD drift)" >&2
  exit 1
fi
echo "CR-schema guard: positive clean + negative-control bite + version-drift check all correct."
