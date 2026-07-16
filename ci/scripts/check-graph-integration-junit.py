#!/usr/bin/env python3
"""Reject skipped or silently missing graph-integration pytest nodes."""

from __future__ import annotations

import argparse
import difflib
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _node_id(testcase: ET.Element) -> str:
    """Convert pytest's JUnit classname/name pair back to a normalized node id."""
    classname = testcase.attrib.get("classname", "")
    name = testcase.attrib.get("name", "")
    parts = classname.split(".")
    try:
        module_index = next(index for index, part in enumerate(parts) if part.startswith("test_"))
    except StopIteration as exc:
        raise ValueError(f"unrecognized pytest classname: {classname!r}") from exc

    path = "/".join(parts[: module_index + 1]) + ".py"
    qualifiers = [*parts[module_index + 1 :], name]
    return "::".join([path, *qualifiers]).replace("\\", "/")


def _manifest_nodes(path: Path) -> list[str]:
    nodes = [
        line.strip().replace("\\", "/") for line in path.read_text(encoding="utf-8").splitlines()
    ]
    return [node for node in nodes if node and not node.startswith("#")]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--junit", type=Path, required=True)
    args = parser.parse_args()

    expected = _manifest_nodes(args.manifest)
    if len(expected) != len(set(expected)):
        print("graph-integration manifest contains duplicate node IDs", file=sys.stderr)
        return 1

    try:
        root = ET.parse(args.junit).getroot()
        cases = root.findall(".//testcase")
        executed = [_node_id(case) for case in cases]
    except (ET.ParseError, OSError, ValueError) as exc:
        print(f"cannot validate graph-integration JUnit: {exc}", file=sys.stderr)
        return 1

    failed = False
    if not executed:
        print("graph-integration JUnit contains no test cases", file=sys.stderr)
        failed = True
    if len(executed) != len(set(executed)):
        print("graph-integration JUnit contains duplicate node IDs", file=sys.stderr)
        failed = True

    expected_sorted = sorted(expected)
    executed_sorted = sorted(executed)
    if executed_sorted != expected_sorted:
        print("executed graph-integration nodes differ from the manifest", file=sys.stderr)
        print(
            "".join(
                difflib.unified_diff(
                    expected_sorted,
                    executed_sorted,
                    fromfile="expected manifest",
                    tofile="executed JUnit",
                    lineterm="\n",
                )
            ),
            file=sys.stderr,
        )
        failed = True

    skipped = [
        node for node, case in zip(executed, cases, strict=True) if case.find("skipped") is not None
    ]
    if skipped:
        print("selected graph-integration tests skipped:", file=sys.stderr)
        for node in skipped:
            print(f"  {node}", file=sys.stderr)
        failed = True

    if failed:
        return 1
    print(f"graph-integration JUnit guard: {len(executed)} exact nodes, zero skips")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
