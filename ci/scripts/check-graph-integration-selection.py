#!/usr/bin/env python3
"""Compare exact graph-integration collection nodes without hiding duplicates."""

from __future__ import annotations

import argparse
import difflib
import sys
from collections import Counter
from pathlib import Path


def _nodes(path: Path) -> list[str]:
    nodes = [
        line.strip().replace("\\", "/") for line in path.read_text(encoding="utf-8").splitlines()
    ]
    return [node for node in nodes if node and not node.startswith("#")]


def _duplicates(nodes: list[str]) -> list[str]:
    return sorted(node for node, count in Counter(nodes).items() if count > 1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--collected", type=Path, required=True)
    args = parser.parse_args()

    expected = _nodes(args.expected)
    collected = _nodes(args.collected)
    expected_duplicates = _duplicates(expected)
    if expected_duplicates:
        print(
            "expected graph-integration manifest contains duplicate node IDs:",
            file=sys.stderr,
        )
        for node in expected_duplicates:
            print(f"  {node}", file=sys.stderr)
        return 1

    collected_duplicates = _duplicates(collected)
    if collected_duplicates:
        print("collected graph-integration nodes contain duplicates:", file=sys.stderr)
        for node in collected_duplicates:
            print(f"  {node}", file=sys.stderr)
        return 1

    expected_sorted = sorted(expected)
    collected_sorted = sorted(collected)
    if expected_sorted != collected_sorted:
        print("collected graph-integration nodes differ from the manifest", file=sys.stderr)
        print(
            "".join(
                difflib.unified_diff(
                    expected_sorted,
                    collected_sorted,
                    fromfile="expected manifest",
                    tofile="collected nodes",
                    lineterm="\n",
                )
            ),
            file=sys.stderr,
        )
        return 1

    print(f"graph-integration selection guard: {len(collected)} exact collected nodes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
