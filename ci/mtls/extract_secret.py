#!/usr/bin/env python3
"""Extract + base64-decode one Secret data key from a rendered Helm manifest.

Usage: extract_secret.py <rendered.yaml> <secret-name> <data-key>

Prints the decoded value (PEM) to stdout. Used by ci/mtls/render-twice.sh to pull
the dev-fallback mTLS cert material out of a `helm template` render for the L4
idempotency / consistency checks.

STDLIB ONLY (no PyYAML) so the CI `infra` job needs no extra pip install. The
render is well-formed Helm output: `---`-separated documents, each Secret has a
`metadata:`/`name:` and a `data:` block whose keys are `  <key>: <base64>` on one
line. We scan for the target Secret document, then its data key. This is a
narrow, render-shape-specific parser (not a general YAML reader) — sufficient for
the fixed structure templates/mtls-postgres.yaml emits.
"""

from __future__ import annotations

import base64
import sys


def _documents(text: str) -> list[str]:
    return text.split("\n---")


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <rendered.yaml> <secret-name> <data-key>", file=sys.stderr)
        return 2
    path, name, key = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(path, encoding="utf-8") as handle:
        text = handle.read()

    for doc in _documents(text):
        lines = doc.splitlines()
        is_secret = any(line.strip() == "kind: Secret" for line in lines)
        if not is_secret:
            continue
        # The metadata name (first `  name:` under metadata; Secret names are unique).
        names = [
            line.split("name:", 1)[1].strip()
            for line in lines
            if line.lstrip().startswith("name:")
        ]
        if name not in names:
            continue
        # Find the data key line: `  <key>: <base64>` (indented two spaces under data:).
        in_data = False
        for line in lines:
            stripped = line.strip()
            if stripped == "data:":
                in_data = True
                continue
            if in_data and stripped and not line.startswith(" "):
                in_data = False
            if in_data and stripped.startswith(f"{key}:"):
                value = stripped.split(":", 1)[1].strip()
                sys.stdout.buffer.write(base64.b64decode(value))
                return 0
        print(f"key {key!r} not found in Secret {name!r}", file=sys.stderr)
        return 1

    print(f"Secret {name!r} not found in {path!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
