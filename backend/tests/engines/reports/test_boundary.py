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
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import AuditLog, Base
from app.models.change_requests import (
    Approval,
    ApprovalDecision,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
)
from app.models.dispatch_outbox import DispatchOutbox
from app.models.identity import Role, User
from app.models.reports import ReportKind
from app.services.audit import service as audit_actions
from app.services.report_outbox import enqueue_report
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

_RENDER_MODULE = "app.engines.reports.render"


def _package_of(path: Path) -> str:
    """The dotted package containing *path* (for relative-import resolution)."""
    rel = path.relative_to(_APP_DIR.parent).with_suffix("")
    return ".".join(rel.parts[:-1])


def _dotted_chain(node: ast.AST) -> str | None:
    """``a.b.c`` for a pure Name/Attribute chain, ``None`` otherwise."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _render_path_violations(tree: ast.Module, package: str) -> list[str]:
    """AST-resolved reaches into the private renderers / raw WeasyPrint surface.

    A regex scanner missed ``from app.engines.reports import render`` followed
    by ``render._render_pdf(...)`` (PR #166 F3). This resolves imports AND
    attribute chains: every import binding that can reach the render module
    (aliased, dotted, or relative) is tracked, and any attribute chain that
    resolves to ``app.engines.reports.render._*`` is flagged — as is a direct
    import of a ``_``-private render name, any weasyprint import, and any
    ``write_pdf`` attribute access.
    """
    aliases: dict[str, str] = {}
    violations: list[str] = []

    def _absolute_module(node: ast.ImportFrom) -> str:
        if node.level == 0:
            return node.module or ""
        base = package.split(".") if package else []
        if node.level > 1:
            base = base[: len(base) - (node.level - 1)]
        return ".".join([*base, node.module]) if node.module else ".".join(base)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "weasyprint" or alias.name.startswith("weasyprint."):
                    violations.append(f"import {alias.name}")
                elif alias.asname is not None:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom):
            module = _absolute_module(node)
            if module == "weasyprint" or module.startswith("weasyprint."):
                violations.append(f"from {module} import ...")
                continue
            for alias in node.names:
                if alias.name == "*":
                    if module == _RENDER_MODULE:
                        violations.append(f"from {module} import *")
                    continue
                imported = f"{module}.{alias.name}" if module else alias.name
                if imported.startswith(f"{_RENDER_MODULE}._"):
                    violations.append(f"from {module} import {alias.name}")
                    continue
                aliases[alias.asname or alias.name] = imported

    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if node.attr == "write_pdf":
            violations.append("attribute write_pdf")
        chain = _dotted_chain(node)
        if chain is None:
            continue
        first, _, rest = chain.partition(".")
        resolved = aliases.get(first, first) + (f".{rest}" if rest else "")
        if resolved.startswith(f"{_RENDER_MODULE}._"):
            violations.append(f"attribute access {chain}")
    return violations


def test_no_second_render_path_exists() -> None:
    """Only engines/reports/render.py may touch the private renderers/WeasyPrint."""
    render_py = _REPORTS_DIR / "render.py"
    offenders: list[str] = []
    for path in _python_files(_APP_DIR):
        if path == render_py:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for violation in _render_path_violations(tree, _package_of(path)):
            offenders.append(f"{path.relative_to(_APP_DIR)}: {violation}")
    assert offenders == [], (
        "a second payload→artifact path would bypass the redaction choke point "
        f"(ADR-0053 §6): {offenders}"
    )


@pytest.mark.parametrize(
    "planted",
    [
        # The exact PR #166 F3 regex miss: module import + attribute access.
        "from app.engines.reports import render\nrender._render_pdf(payload)\n",
        "from app.engines.reports import render as r\nr._render_pdf(payload)\n",
        "import app.engines.reports.render as rr\nrr._render_csv(payload)\n",
        "import app.engines.reports.render\napp.engines.reports.render._render_pdf(p)\n",
        "import app.engines.reports as reports\nreports.render._render_pdf(p)\n",
        "from app.engines import reports\nreports.render._render_pdf(p)\n",
        "from app.engines.reports.render import _render_pdf\n",
        "from app.engines.reports.render import _render_pdf as make\n",
        "import weasyprint\n",
        "from weasyprint import HTML\n",
        "doc.write_pdf(target)\n",
    ],
)
def test_render_path_scanner_catches_planted_violations(planted: str) -> None:
    """The AST scanner BITES on aliased/module-level access to render internals."""
    assert _render_path_violations(ast.parse(planted), "app.planted") != []


def test_render_path_scanner_resolves_relative_imports() -> None:
    """``from . import render`` inside the reports package is still tracked."""
    planted = "from . import render\nrender._render_pdf(payload)\n"
    assert _render_path_violations(ast.parse(planted), "app.engines.reports") != []


def test_render_path_scanner_permits_the_public_entry_point() -> None:
    """Public access (``render_artifacts``) is the sanctioned path — no flag."""
    public = "from app.engines.reports import render_artifacts\nrender_artifacts(p)\n"
    assert _render_path_violations(ast.parse(public), "app.ok") == []
    via_module = "from app.engines.reports import render\nrender.render_artifacts(p)\n"
    assert _render_path_violations(ast.parse(via_module), "app.ok") == []
    unrelated = "render = object()\nrender._render_pdf\n"  # not the module: no import
    assert _render_path_violations(ast.parse(unrelated), "app.ok") == []


def test_single_render_path_scanner_is_not_vacuous() -> None:
    """The names the scanner guards still exist in the real renderer file."""
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
def generation_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[str], dict[ReportKind, tuple[uuid.UUID, uuid.UUID]]]:
    """File-backed schema + a cursor-level statement capture on the task seam."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'boundary.sqlite'}"
    captured: list[str] = []
    dispatches: dict[ReportKind, tuple[uuid.UUID, uuid.UUID]] = {}

    async def _create_schema() -> None:
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # Seed one CR + approval + lifecycle audit row + identities INSIDE the
        # generation period: on an EMPTY database the change builder's
        # ``_load_identities`` early-returns before issuing SQL, leaving the
        # password_hash deny-column assertion VACUOUS for the change kind
        # (PR #166 F3). Seeded on this SEPARATE engine so the seed INSERTs
        # (which legitimately carry ``password_hash``) are never captured.
        maker = async_sessionmaker(engine, expire_on_commit=False)
        role_id, user_id, cr_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
        seeded_at = datetime(2026, 7, 2, 10, tzinfo=UTC)
        async with maker() as session:
            session.add(Role(id=role_id, name="engineer"))
            session.add(
                User(
                    id=user_id,
                    username="boundary-user",
                    password_hash="x",
                    role_id=role_id,
                    is_active=True,
                    idp_iss="https://idp.example.test",
                    idp_subject="idp-sub-boundary",
                )
            )
            session.add(
                ChangeRequest(
                    id=cr_id,
                    state=ChangeRequestState.APPROVED,
                    kind=ChangeRequestKind.CONFIG,
                    requester_id=user_id,
                    four_eyes_required=True,
                    created_at=seeded_at,
                    updated_at=seeded_at,
                )
            )
            session.add(
                Approval(
                    change_request_id=cr_id,
                    actor_id=user_id,
                    decision=ApprovalDecision.APPROVE,
                    created_at=seeded_at,
                )
            )
            session.add(
                AuditLog(
                    actor=f"user:{user_id}",
                    action=audit_actions.CHANGE_REQUEST_CREATED,
                    target_type="change_request",
                    target_id=str(cr_id),
                    created_at=seeded_at,
                )
            )
            for kind in ReportKind:
                run_id = uuid.uuid4()
                await enqueue_report(
                    session,
                    run_id=run_id,
                    kind=kind,
                    period_start=datetime(2026, 7, 1, tzinfo=UTC),
                    period_end=datetime(2026, 7, 8, tzinfo=UTC),
                    trigger="on_demand",
                    requested_by=None,
                )
                dispatch_id = (
                    await session.execute(
                        select(DispatchOutbox.id).where(DispatchOutbox.aggregate_id == run_id)
                    )
                ).scalar_one()
                dispatches[kind] = (dispatch_id, run_id)
            await session.commit()
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
    return captured, dispatches


def test_generation_touches_no_deny_set_table_for_any_kind(
    generation_boundary: tuple[
        list[str],
        dict[ReportKind, tuple[uuid.UUID, uuid.UUID]],
    ],
) -> None:
    statements, dispatches = generation_boundary
    per_kind: dict[str, list[str]] = {}
    for kind in ReportKind:
        before = len(statements)
        dispatch_id, run_id = dispatches[kind]
        result = asyncio.run(
            report_tasks._generate_report_core(
                str(dispatch_id),
                str(run_id),
            )
        )
        assert result["status"] == "succeeded", result
        per_kind[kind.value] = statements[before:]

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
    # Anti-vacuous for the CHANGE kind (PR #166 F3): the seeded CR/approval/
    # lifecycle rows force ``_load_identities`` to actually emit its users
    # query, so the password_hash deny-column assertion above observed the
    # exact statement class it guards for the change report too.
    change_sql = "\n".join(s.lower() for s in per_kind[ReportKind.CHANGE.value])
    assert re.search(r"from\s+users\b", change_sql), (
        "the change generation never queried users — the identity projection "
        "was not exercised and the deny-column proof is vacuous for this kind"
    )
    # Reports are NEVER the RAG-embedded documents table (ADR-0053 §1): no
    # generation statement may write into it.
    assert not re.search(r"insert\s+into\s+documents\b", joined)
    assert not re.search(r"update\s+documents\b", joined)
    # ...and the artifacts DID land in the dedicated report tables.
    assert re.search(r"insert\s+into\s+report_artifacts\b", joined)


def test_deny_table_scanner_is_not_vacuous(
    generation_boundary: tuple[
        list[str],
        dict[ReportKind, tuple[uuid.UUID, uuid.UUID]],
    ],
) -> None:
    """A planted deny-set SELECT is caught by the same capture mechanism."""
    statements, _dispatches = generation_boundary

    async def _planted() -> None:
        async with report_tasks._session() as session:
            from sqlalchemy import text

            await session.execute(text("SELECT id FROM device_credentials"))

    asyncio.run(_planted())
    assert any("device_credentials" in s.lower() for s in statements)
