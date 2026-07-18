"""Structural boundary proofs (P4 W3-T1; ADR-0053 §6 layer 1 + §1).

1. **Single render path** — no app code outside ``engines/reports/render.py``
   references the private renderers or the raw WeasyPrint surface; the only
   payload→artifact entry point is ``render_artifacts`` (which contains the
   redaction choke point).
2. **Source-allowlist imports** — no module in ``app.engines.reports`` imports
   a deny-set surface (credential vault/KMS, LLM, knowledge). The
   import-linter contract in pyproject enforces this at the gate; this AST
   check makes the same boundary bite inside pytest.
3. **No SELECT against deny-set tables at runtime** — a REAL generation run
   (per kind) is instrumented at the SQLAlchemy cursor and every executed
   statement is captured: none may touch ``device_credentials``,
   ``raw_artifacts``, or ``config_snapshots``, and none may write to the
   RAG-embedded ``documents`` table (reports are NEVER embedded, ADR-0053 §1).
   The capture asserts it saw statements (anti-vacuous).
"""

from __future__ import annotations

import ast
import asyncio
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import create_async_engine

from app.models import Base
from app.models.reports import ReportKind
from app.workers.tasks import reports as report_tasks

_APP_DIR = Path(__file__).resolve().parents[3] / "app"
_REPORTS_DIR = _APP_DIR / "engines" / "reports"

#: ADR-0053 §6 layer 1 deny-set import surfaces for app.engines.reports.
_DENY_IMPORTS = (
    "app.core.crypto",
    "app.knowledge",
    "app.llm",
    "app.services.credentials",
)

#: Deny-set tables no report generation statement may touch (§6 layer 1), plus
#: the RAG-embedded documents table no generation statement may WRITE (§1).
#: ``refresh_sessions`` joined in W3-T4: session data is credential-adjacent —
#: the access-review report derives last-login from AUDIT events, never from
#: the session table.
_DENY_TABLES = ("device_credentials", "raw_artifacts", "config_snapshots", "refresh_sessions")

#: Credential-adjacent COLUMNS no generation statement may select (W3-T4): the
#: access-review builder must project explicit ``users`` columns — a full-row
#: ``SELECT users.*`` would drag the bcrypt hash into the report engine.
_DENY_COLUMNS = ("password_hash",)


def _python_files(root: Path) -> Iterator[Path]:
    yield from root.rglob("*.py")


# ---------------------------------------------------------------------------
# 1. Single render path
# ---------------------------------------------------------------------------


def test_no_second_render_path_exists() -> None:
    """Only engines/reports/render.py may touch the private renderers/WeasyPrint."""
    render_py = _REPORTS_DIR / "render.py"
    # The raw WeasyPrint surface, plus any reach into the private renderers of
    # engines/reports/render.py (an unqualified ``_render_csv`` elsewhere is a
    # different module's own helper — e.g. the documentation tools' inventory
    # CSV — and is not a report artifact path).
    pattern = re.compile(
        r"write_pdf|import weasyprint|from weasyprint"
        r"|app\.engines\.reports\.render import _"
        r"|reports\.render\._render"
    )
    offenders: list[str] = []
    for path in _python_files(_APP_DIR):
        if path == render_py:
            continue
        if pattern.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(_APP_DIR)))
    assert offenders == [], (
        "a second payload→artifact path would bypass the redaction choke point "
        f"(ADR-0053 §6): {offenders}"
    )


def test_single_render_path_scanner_is_not_vacuous() -> None:
    """The scanner's pattern matches the real renderer file (no silent no-op)."""
    text = (_REPORTS_DIR / "render.py").read_text(encoding="utf-8")
    assert "_render_csv" in text and "write_pdf" in text


# ---------------------------------------------------------------------------
# 2. Deny-set imports (AST — bites in pytest, mirrored by import-linter)
# ---------------------------------------------------------------------------


def test_reports_engine_imports_no_deny_surface() -> None:
    offenders: list[str] = []
    for path in _python_files(_REPORTS_DIR):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if any(name == deny or name.startswith(f"{deny}.") for deny in _DENY_IMPORTS):
                    offenders.append(f"{path.name}: {name}")
    assert offenders == [], f"deny-set import in app.engines.reports (ADR-0053 §6): {offenders}"


# ---------------------------------------------------------------------------
# 3. Runtime no-SELECT-deny-set proof over a REAL generation per kind
# ---------------------------------------------------------------------------


@pytest.fixture()
def statements(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """File-backed schema + a cursor-level statement capture on the task seam."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'boundary.sqlite'}"
    captured: list[str] = []

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()

    asyncio.run(_create_schema())

    def _make_instrumented_engine() -> Any:
        engine = create_async_engine(url)

        @event.listens_for(engine.sync_engine, "before_cursor_execute")
        def _capture(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
            captured.append(statement)

        return engine

    monkeypatch.setattr(report_tasks, "_make_engine", _make_instrumented_engine)
    # Stub only the native-lib PDF step; the choke point + CSV render stay real.
    from app.engines.reports import render

    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    return captured


def test_generation_touches_no_deny_set_table_for_any_kind(statements: list[str]) -> None:
    for kind in ReportKind:
        result = asyncio.run(
            report_tasks._generate_report_core(
                kind.value,
                "2026-07-01T00:00:00+00:00",
                "2026-07-08T00:00:00+00:00",
                "on_demand",
                None,
            )
        )
        assert result["status"] == "succeeded", result

    # Anti-vacuous: the capture MUST have observed the generation's SQL.
    assert len(statements) > 0
    joined = "\n".join(s.lower() for s in statements)
    for table in _DENY_TABLES:
        assert table not in joined, (
            f"report generation issued SQL touching deny-set table {table!r} "
            "(ADR-0053 §6 layer 1 — what is never queried can never leak)"
        )
    for column in _DENY_COLUMNS:
        assert column not in joined, (
            f"report generation issued SQL selecting credential-adjacent column "
            f"{column!r} (W3-T4: the access-review builder must project explicit "
            "secret-free columns, never the full users row)"
        )
    # Anti-vacuous for the W3-T4 assertions: the access-review generation DID
    # read the users table (so the column check observed the relevant SQL).
    assert re.search(r"from\s+users\b", joined)
    # Reports are NEVER the RAG-embedded documents table (ADR-0053 §1): no
    # generation statement may write into it.
    assert not re.search(r"insert\s+into\s+documents\b", joined)
    assert not re.search(r"update\s+documents\b", joined)
    # ...and the artifacts DID land in the dedicated report tables.
    assert re.search(r"insert\s+into\s+report_artifacts\b", joined)


def test_deny_table_scanner_is_not_vacuous(statements: list[str]) -> None:
    """A planted deny-set SELECT is caught by the same capture mechanism."""

    async def _planted() -> None:
        async with report_tasks._session() as session:
            from sqlalchemy import text

            await session.execute(text("SELECT id FROM device_credentials"))

    asyncio.run(_planted())
    assert any("device_credentials" in s.lower() for s in statements)
