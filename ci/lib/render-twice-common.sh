#!/usr/bin/env bash
# Shared lifecycle for the CNPG, mTLS, and Redis render-twice bite proofs.

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "::error::render-twice-common.sh must be sourced" >&2
  exit 2
fi

set -euo pipefail

render_twice_init() {
  RENDER_TWICE_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "${RENDER_TWICE_LIB_DIR}/../.." && pwd)"
  CHART_DIR="${REPO_ROOT}/deploy/kubernetes/netops"
  export PATH="${HOME:+${HOME}/.local/bin:}${PATH}"

  WORK="$(mktemp -d)"
  trap 'rm -rf "${WORK}"' EXIT

  fail=0
  PY="$(command -v python3 || command -v python || true)"
  if [ -z "${PY}" ]; then
    echo "::error::no python3/python on PATH for the render-twice extractor" >&2
    return 2
  fi
}

ok() { echo "PASS: $*"; }

bad() {
  echo "FAIL: $*" >&2
  fail=$((fail + 1))
}

render_twice_require_nonempty() {
  if [ ! -s "$1" ]; then
    echo "::error::render produced an empty manifest: $1" >&2
    return 1
  fi
}

extract_rendered_secret() {
  if [ "$#" -ne 4 ]; then
    echo "::error::extract_rendered_secret requires MODE FILE SECRET KEY" >&2
    return 2
  fi
  "${PY}" "${REPO_ROOT}/ci/lib/extract-rendered-secret.py" "$@"
}

render_twice_finish() {
  if [ "$#" -ne 2 ]; then
    echo "::error::render_twice_finish requires SUMMARY_LABEL GUARD_LABEL" >&2
    return 2
  fi
  local summary_label="$1"
  local guard_label="$2"
  echo "== ${summary_label} summary: ${fail} failure(s) =="
  if [ "${fail}" -ne 0 ]; then
    echo "::error::${guard_label} found ${fail} violation(s)" >&2
    return 1
  fi
  echo "${guard_label}: all invariants hold."
}
