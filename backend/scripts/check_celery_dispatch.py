#!/usr/bin/env python3
"""Reject Celery publication that bypasses the hardened dispatch boundary."""

from __future__ import annotations

import argparse
import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

FORBIDDEN_METHODS = frozenset({"send_task", "apply_async", "delay"})
_WRAPPER_PATH = Path("app/workers/dispatch.py")
_WRAPPER_SYMBOL = "durable_dispatch"


@dataclass(frozen=True)
class ExceptionScope:
    path: Path
    symbol: str
    kind: str


@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    symbol: str
    kind: str


class _PublicationVisitor(ast.NodeVisitor):
    def __init__(self, path: Path, exceptions: frozenset[ExceptionScope]) -> None:
        self.path = path.resolve()
        self.exceptions = exceptions
        self.symbols: list[str] = []
        self.violations: list[Violation] = []

    @property
    def symbol(self) -> str:
        return ".".join(self.symbols) if self.symbols else "<module>"

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.symbols.append(node.name)
        self.generic_visit(node)
        self.symbols.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.symbols.append(node.name)
        self.generic_visit(node)
        self.symbols.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN_METHODS:
            kind = node.func.attr
            scope = ExceptionScope(self.path, self.symbol, kind)
            wrapper_call = self.path.as_posix().endswith(_WRAPPER_PATH.as_posix()) and (
                self.symbol == _WRAPPER_SYMBOL
            )
            if not wrapper_call and scope not in self.exceptions:
                self.violations.append(Violation(self.path, node.lineno, self.symbol, kind))
        self.generic_visit(node)


def _python_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(path.rglob("*.py"))
        elif path.suffix == ".py":
            yield path


def scan_paths(
    paths: Iterable[Path],
    *,
    exceptions: frozenset[ExceptionScope] = frozenset(),
) -> list[Violation]:
    violations: list[Violation] = []
    for path in _python_files(paths):
        visitor = _PublicationVisitor(path, exceptions)
        visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        violations.extend(visitor.violations)
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--negative-control", action="store_true")
    args = parser.parse_args()
    backend = Path(__file__).resolve().parents[1]
    paths = (
        [backend / "tests" / "fixtures" / "celery_dispatch_ratchet"]
        if args.negative_control
        else args.paths or [backend / "app"]
    )
    violations = scan_paths(paths)
    for violation in violations:
        print(f"{violation.kind} {violation.path}:{violation.line} ({violation.symbol})")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
