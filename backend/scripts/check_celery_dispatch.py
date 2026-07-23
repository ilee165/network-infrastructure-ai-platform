#!/usr/bin/env python3
"""Reject Celery publication that bypasses the hardened dispatch boundary."""

from __future__ import annotations

import argparse
import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

FORBIDDEN_METHODS = frozenset({"send_task", "apply_async", "delay"})
TRACK_BOUND_METHOD_ALIAS = True
TRACK_IMPORTED_TASK_ALIAS = True
TRACK_IMPORTED_TASK_METHOD = True
_BACKEND = Path(__file__).resolve().parents[1]
_WRAPPER_PATH = (_BACKEND / "app" / "workers" / "dispatch.py").resolve()
_WRAPPER_SYMBOL = "durable_dispatch"
_TASK_MODULE_PREFIX = "app.workers.tasks"


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
    def __init__(
        self,
        path: Path,
        exceptions: frozenset[ExceptionScope],
        task_symbols: dict[str, frozenset[str]],
    ) -> None:
        self.path = path.resolve()
        self.exceptions = exceptions
        self.task_symbols = task_symbols
        self.symbols: list[str] = []
        self.violations: list[Violation] = []
        self.method_aliases: dict[str, str] = {}
        self.imported_task_aliases: set[str] = set()
        self.imported_task_modules: dict[str, str] = {}

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

    def visit_Import(self, node: ast.Import) -> None:
        if TRACK_IMPORTED_TASK_METHOD:
            for imported in node.names:
                if imported.name in self.task_symbols:
                    bound_name = imported.asname or imported.name.split(".")[0]
                    self.imported_task_modules[bound_name] = imported.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        for imported in node.names:
            bound_name = imported.asname or imported.name
            imported_module = f"{node.module}.{imported.name}"
            if imported_module in self.task_symbols:
                if TRACK_IMPORTED_TASK_METHOD:
                    self.imported_task_modules[bound_name] = imported_module
            elif TRACK_IMPORTED_TASK_ALIAS and imported.name in self.task_symbols.get(
                node.module, frozenset()
            ):
                self.imported_task_aliases.add(bound_name)

    @staticmethod
    def _bound_names(node: ast.expr) -> Iterable[str]:
        if isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, (ast.Tuple, ast.List)):
            for item in node.elts:
                yield from _PublicationVisitor._bound_names(item)

    def _track_assignment(self, targets: Iterable[ast.expr], value: ast.expr) -> None:
        names = [name for target in targets for name in self._bound_names(target)]
        if (
            TRACK_BOUND_METHOD_ALIAS
            and isinstance(value, ast.Attribute)
            and value.attr in FORBIDDEN_METHODS
        ):
            for name in names:
                self.method_aliases[name] = value.attr
        if (
            TRACK_IMPORTED_TASK_ALIAS
            and isinstance(value, ast.Name)
            and value.id in self.imported_task_aliases
        ):
            self.imported_task_aliases.update(names)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._track_assignment(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._track_assignment([node.target], node.value)
        self.generic_visit(node)

    @staticmethod
    def _attribute_root(node: ast.Attribute) -> str | None:
        value: ast.expr = node
        while isinstance(value, ast.Attribute):
            value = value.value
        return value.id if isinstance(value, ast.Name) else None

    def _is_imported_task_attribute(self, node: ast.Attribute) -> bool:
        root = self._attribute_root(node)
        if root is None or root not in self.imported_task_modules:
            return False
        module = self.imported_task_modules[root]
        return node.attr in self.task_symbols[module]

    def _record(self, node: ast.Call, kind: str) -> None:
        scope = ExceptionScope(self.path, self.symbol, kind)
        wrapper_call = self.path == _WRAPPER_PATH and self.symbol == _WRAPPER_SYMBOL
        if not wrapper_call and scope not in self.exceptions:
            self.violations.append(Violation(self.path, node.lineno, self.symbol, kind))

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute) and node.func.attr in FORBIDDEN_METHODS:
            self._record(node, node.func.attr)
        elif isinstance(node.func, ast.Name) and node.func.id in self.method_aliases:
            self._record(node, self.method_aliases[node.func.id])
        elif (
            TRACK_IMPORTED_TASK_ALIAS
            and isinstance(node.func, ast.Name)
            and node.func.id in self.imported_task_aliases
        ) or (
            TRACK_IMPORTED_TASK_METHOD
            and isinstance(node.func, ast.Attribute)
            and self._is_imported_task_attribute(node.func)
        ):
            self._record(node, "task_call")
        self.generic_visit(node)


def _task_symbols() -> dict[str, frozenset[str]]:
    task_root = _BACKEND / "app" / "workers" / "tasks"
    symbols: dict[str, frozenset[str]] = {}
    for path in task_root.glob("*.py"):
        module = f"{_TASK_MODULE_PREFIX}.{path.stem}"
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        task_names = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and decorator.func.attr == "task"
                for decorator in node.decorator_list
            )
        }
        symbols[module] = frozenset(task_names)
    return symbols


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
    task_symbols = _task_symbols()
    for path in _python_files(paths):
        visitor = _PublicationVisitor(path, exceptions, task_symbols)
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
