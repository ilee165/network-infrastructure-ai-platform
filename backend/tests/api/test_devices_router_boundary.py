"""Architecture guard for the devices HTTP/service boundary."""

from __future__ import annotations

import ast
from pathlib import Path

ROUTER = Path(__file__).parents[2] / "app" / "api" / "v1" / "devices.py"


def test_devices_router_is_orm_free() -> None:
    """No direct model import or session operation crosses the router seam."""
    tree = ast.parse(ROUTER.read_text(encoding="utf-8"))
    forbidden_imports: list[str] = []
    forbidden_calls: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            forbidden_imports.extend(
                alias.name for alias in node.names if alias.name.startswith("app.models")
            )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.startswith("app.models"):
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


def test_devices_router_preserves_boundary_types() -> None:
    """Dependency annotations may not be erased to ``Any``."""
    tree = ast.parse(ROUTER.read_text(encoding="utf-8"))
    any_references = [
        node.lineno for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "Any"
    ]
    assert any_references == []
