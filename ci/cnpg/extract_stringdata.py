#!/usr/bin/env python3
"""Extract one Secret stringData value from a rendered Helm manifest.

Usage: extract_stringdata.py <rendered.yaml> <secret-name> <data-key>

Prints the value (verbatim, with surrounding quotes stripped) to stdout. Used by
ci/cnpg/render-twice.sh to pull the dev-fallback CNPG credential PASSWORD out of a
`helm template` render for the L4 idempotency checks.

STDLIB ONLY (no PyYAML) so the CI `infra` job needs no extra pip install. The
render is well-formed Helm output: `---`-separated documents, each Secret has a
`metadata:`/`name:` and a `stringData:` block whose keys are `  <key>: <value>` on
one line. We scan for the target Secret document, then its stringData key. This is
a narrow, render-shape-specific parser (not a general YAML reader) — sufficient
for the fixed structure cloudnativepg-secret.yaml emits.

Hardening (mirrors ci/mtls/extract_secret.py):
  - The Secret is matched on `metadata.name` ONLY (the first `name:` under the
    top-level `metadata:` block), never on any `name:` field anywhere in the doc.
"""

from __future__ import annotations

import sys


def _documents(text: str) -> list[str]:
    return text.split("\n---")


def _metadata_name(lines: list[str]) -> str | None:
    in_meta = False
    for line in lines:
        if line.startswith("metadata:"):
            in_meta = True
            continue
        if in_meta:
            # End of the metadata block: a non-indented, non-empty line.
            if line and not line[0].isspace():
                in_meta = False
                continue
            stripped = line.strip()
            if stripped.startswith("name:"):
                return stripped.split("name:", 1)[1].strip()
    return None


def _stringdata_value(lines: list[str], key: str) -> str | None:
    in_block = False
    for line in lines:
        if line.startswith("stringData:"):
            in_block = True
            continue
        if in_block:
            if line and not line[0].isspace():
                in_block = False
                continue
            stripped = line.strip()
            prefix = f"{key}:"
            if stripped.startswith(prefix):
                val = stripped[len(prefix):].strip()
                # Strip a single layer of surrounding quotes (helm `| quote`).
                if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                    val = val[1:-1]
                return val
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        sys.stderr.write(
            "usage: extract_stringdata.py <rendered.yaml> <secret-name> <data-key>\n"
        )
        return 2
    path, secret_name, data_key = argv[1], argv[2], argv[3]
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    for doc in _documents(text):
        lines = doc.splitlines()
        if _metadata_name(lines) != secret_name:
            continue
        val = _stringdata_value(lines, data_key)
        if val is not None:
            sys.stdout.write(val)
            return 0
    sys.stderr.write(
        f"key {data_key!r} not found in Secret {secret_name!r} in {path}\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
