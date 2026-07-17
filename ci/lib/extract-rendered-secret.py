#!/usr/bin/env python3
"""Extract one value from a rendered Kubernetes Secret.

This is intentionally a narrow, standard-library-only reader for the stable
shape emitted by ``helm template``. It is not a general YAML parser. The
``data`` mode strictly base64-decodes bytes; ``stringData`` returns the scalar
text after removing one YAML quoting layer.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

_DOCUMENT_BOUNDARY = re.compile(r"(?m)^---[ \t]*(?:#.*)?\r?$")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _unquote(value: str) -> str:
    if len(value) < 2 or value[0] != value[-1] or value[0] not in {"'", '"'}:
        return value
    if value[0] == "'":
        return value[1:-1].replace("''", "'")
    decoded = json.loads(value)
    if not isinstance(decoded, str):
        raise ValueError("quoted scalar is not a string")
    return decoded


def _top_level_value(lines: list[str], key: str) -> str | None:
    prefix = f"{key}:"
    for line in lines:
        if not line or line.startswith((" ", "\t", "#")):
            continue
        if line.startswith(prefix):
            return _unquote(line[len(prefix) :].strip())
    return None


def _direct_block_value(lines: list[str], block: str, key: str) -> str | None:
    start: int | None = None
    for index, line in enumerate(lines):
        if line == f"{block}:":
            start = index + 1
            break
    if start is None:
        return None

    members: list[str] = []
    for line in lines[start:]:
        if line.strip() and _indent(line) == 0:
            break
        if line.strip() and not line.lstrip().startswith("#"):
            members.append(line)
    if not members:
        return None

    direct_indent = min(_indent(line) for line in members)
    prefix = f"{key}:"
    for line in members:
        if _indent(line) != direct_indent:
            continue
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix) :].strip()
    return None


def _extract(text: str, mode: str, secret_name: str, key: str) -> bytes:
    matched_secret = False
    for document in _DOCUMENT_BOUNDARY.split(text):
        lines = document.splitlines()
        if _top_level_value(lines, "kind") != "Secret":
            continue
        if _direct_block_value(lines, "metadata", "name") != secret_name:
            continue
        matched_secret = True
        value = _direct_block_value(lines, mode, key)
        if value is None:
            continue
        if mode == "stringData":
            return _unquote(value).encode("utf-8")
        try:
            return base64.b64decode(_unquote(value), validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(
                f"key {key!r} in Secret {secret_name!r} is not valid base64: {exc}"
            ) from exc

    if matched_secret:
        raise ValueError(f"key {key!r} not found in Secret {secret_name!r}")
    raise ValueError(f"Secret {secret_name!r} not found")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("data", "stringData"))
    parser.add_argument("rendered_manifest", type=Path)
    parser.add_argument("secret_name")
    parser.add_argument("data_key")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        text = args.rendered_manifest.read_text(encoding="utf-8")
        value = _extract(text, args.mode, args.secret_name, args.data_key)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"extract-rendered-secret: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
