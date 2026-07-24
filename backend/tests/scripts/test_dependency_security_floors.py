"""Security floors that must remain direct, lock-governed dependencies."""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement

_BACKEND = Path(__file__).resolve().parents[2]


def test_pyasn1_security_floor_covers_2026_dos_fixes() -> None:
    project = tomllib.loads((_BACKEND / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = {
        requirement.name: requirement
        for raw in project["project"]["dependencies"]
        for requirement in [Requirement(raw)]
    }

    assert "pyasn1" in dependencies
    assert dependencies["pyasn1"].specifier.contains("0.6.4")
