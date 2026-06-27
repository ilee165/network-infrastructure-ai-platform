#!/usr/bin/env bash
# Assertion-runner entrypoint for the W4-T3 kind harness (ADR-0039 §6, ADR-0041 §3).
#
# This is the reusable scaffold W4-T4 (mTLS handshake / plaintext-refusal) and
# W4-T5 (collector egress allow / deny) plug their assertions into. Each task
# drops one or more executable `*.sh` files under
#   ci/kind/assertions/checks/
# Each check sources lib.sh, performs its assertions via the assert_* helpers,
# and is expected to leave a non-zero ASSERT_FAIL count (and/or exit non-zero) on
# any failed assertion.
#
# CONTRACT (the bite): the runner exits NON-ZERO if ANY check fails — either by
# returning non-zero itself OR by recording an assert_* failure. A green run
# means every check passed. The harness calls this only AFTER the CNI self-test
# passes (ADR-0041 §2/§3) — assertions never run on an unproven (non-enforcing)
# CNI.
#
# L5 (P1-W4-LESSONS): `set -o pipefail` is on globally so a masked exit inside a
# piped check cannot read green; each check's output is teed to a log and the
# runner asserts the log is non-empty (`test -s`).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKS_DIR="${HERE}/checks"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

# Where to write per-check logs (CI uploads these as artifacts; the harness sets
# ASSERT_LOG_DIR, falling back to a temp dir for a bare local run).
LOG_DIR="${ASSERT_LOG_DIR:-$(mktemp -d)}"
mkdir -p "${LOG_DIR}"

echo "== W4 kind assertion-runner =="
echo "checks dir: ${CHECKS_DIR}"
echo "log dir:    ${LOG_DIR}"

if [ ! -d "${CHECKS_DIR}" ]; then
  echo "::error::checks dir ${CHECKS_DIR} missing — the assertion-runner scaffold is broken" >&2
  exit 2
fi

# Collect checks deterministically (sorted). A run with ZERO checks is allowed
# (the W4-T3 scaffold lands before T4/T5 add theirs) but is reported loudly so it
# is never mistaken for "all assertions passed". nullglob makes a non-matching
# glob expand to NOTHING (not the literal pattern), so an empty checks dir yields
# a zero-length array — globbing straight into the array avoids the `printf '%s\n'`
# trap of emitting one empty line when there are no matches.
shopt -s nullglob
checks=("${CHECKS_DIR}"/*.sh)
shopt -u nullglob
# Sort for deterministic order across filesystems.
if [ "${#checks[@]}" -gt 0 ]; then
  mapfile -t checks < <(printf '%s\n' "${checks[@]}" | sort)
fi

if [ "${#checks[@]}" -eq 0 ]; then
  echo "NOTE: no assertion checks present yet (W4-T4 mTLS + W4-T5 egress add them)."
  echo "      The scaffold is healthy; there is nothing to assert on this run."
  exit 0
fi

run_failures=0
for check in "${checks[@]}"; do
  name="$(basename "${check}")"
  log="${LOG_DIR}/${name}.log"
  echo "::group::assertion check ${name}"
  # pipefail (set above) propagates the check's exit through the `| tee` pipe so
  # a failing check is never masked by tee's exit 0; `test -s` then guards an
  # empty (silently no-op) check log (L5).
  if bash "${check}" 2>&1 | tee "${log}"; then
    status=0
  else
    status=$?
  fi
  if [ ! -s "${log}" ]; then
    echo "::error::check ${name} produced NO output — a silent no-op check is a false-green; failing" >&2
    run_failures=$((run_failures + 1))
  fi
  if [ "${status}" -ne 0 ]; then
    echo "check ${name}: FAIL (exit ${status})"
    run_failures=$((run_failures + 1))
  else
    echo "check ${name}: ok"
  fi
  echo "::endgroup::"
done

echo "== assertion-runner summary: ${run_failures} failed check(s) =="
if [ "${run_failures}" -ne 0 ]; then
  echo "::error::${run_failures} assertion check(s) failed" >&2
  exit 1
fi
echo "all assertion checks passed."
