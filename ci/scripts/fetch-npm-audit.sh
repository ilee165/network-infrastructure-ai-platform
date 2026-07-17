#!/usr/bin/env bash
# Fetch npm audit JSON with bounded transient retries without treating findings
# as a transport failure. The local npm-audit-gate remains the one-shot RED gate.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "--once" ]]; then
  [[ $# -eq 2 ]] || exit 64
  attempt_output="$2"
  attempt_error="$(mktemp)"
  trap 'rm -f "$attempt_error"' EXIT
  set +e
  npm audit --json >"$attempt_output" 2>"$attempt_error"
  npm_status=$?
  set -e

  # A shaped audit report is a completed fetch even when npm exits non-zero for
  # vulnerabilities. Error-shaped/malformed output remains a failed acquisition.
  if node -e '
    const fs = require("fs");
    try {
      const report = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
      if (!report || typeof report !== "object" ||
          !("auditReportVersion" in report) || !("metadata" in report) ||
          !("vulnerabilities" in report)) process.exit(1);
    } catch (_) { process.exit(1); }
  ' "$attempt_output"; then
    cat "$attempt_error" >&2
    exit 0
  fi

  cat "$attempt_output" >&2
  cat "$attempt_error" >&2
  if [[ "$npm_status" -eq 0 ]]; then
    exit 65
  fi
  exit "$npm_status"
fi

if [[ $# -ne 1 ]]; then
  echo "usage: fetch-npm-audit.sh OUTPUT_JSON" >&2
  exit 64
fi

output="$1"
tmp_output="$(mktemp)"
trap 'rm -f "$tmp_output"' EXIT

if bash "$script_dir/retry-egress.sh" --timeout-seconds 180 -- \
  bash "$0" --once "$tmp_output"; then
  mv "$tmp_output" "$output"
else
  status=$?
  exit "$status"
fi
