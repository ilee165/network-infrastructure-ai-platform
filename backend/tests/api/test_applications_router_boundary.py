"""Architecture guard for the applications HTTP/service boundary."""

from __future__ import annotations

import ast
from pathlib import Path

ROUTER = Path(__file__).parents[2] / "app" / "api" / "v1" / "applications.py"


def test_applications_router_is_orm_free() -> None:
    """The router may shape HTTP data, but persistence belongs to its service."""
    tree = ast.parse(ROUTER.read_text(encoding="utf-8"))
    forbidden_imports: list[str] = []
    forbidden_calls: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            forbidden_imports.extend(
                alias.name for alias in node.names if alias.name.startswith("sqlalchemy")
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith(("sqlalchemy", "app.models")):
                forbidden_imports.append(module)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            if (
                isinstance(receiver, ast.Name)
                and receiver.id in {"db", "session"}
                and node.func.attr
                in {"add", "commit", "delete", "execute", "flush", "get", "rollback"}
            ):
                forbidden_calls.append(node.func.attr)

    assert forbidden_imports == []
    assert forbidden_calls == []
