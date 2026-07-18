"""Audit-integrity builder (P4 W3-T5; ADR-0053 §7.4) — unit suite.

The audit-integrity report surfaces the ADR-0038 spine as evidence: per-day
hash-chain verification outcomes read from the PERSISTED
``audit_chain_verification_runs`` history (never re-verified inline), missing
days surfaced as explicit gap FINDINGS, and the append-only grant attestation
run LIVE at generation time.

Covered here (SQLite; the history/period queries and the real-catalog grant
check re-assert on real PostgreSQL in ``tests/pg/test_audit_integrity_pg.py``):

* run/daily section shape with checkpoint digest presentation and range
  tokens (genesis lower bound, verified head);
* a day with no persisted run renders the explicit gap marker AND raises a
  verification-gap finding (a verification that never ran is a finding, not a
  blank); break days and grant-violation days raise findings too;
* the attestation is LIVE per generation (call-counted, never cached) and the
  SQLite backend renders the honest ``unavailable`` token, never a silent
  clean; a violation appends the generation-time finding;
* naive period inputs are pinned as UTC (the W3-T1 phantom-run-id class);
* SHA-256 digest presentation passes the redaction choke point
  (format-anchored patterns, no entropy detection — spec requirement 4) while
  a planted PEM value still fails CLOSED;
* the golden CSV/PDF structure fixture for W4-T3's conformance checks.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.engines.reports import audit_integrity as audit_integrity_module
from app.engines.reports import build_payload, render_artifacts
from app.engines.reports.audit_integrity import (
    ATTEST_CLEAN,
    ATTEST_UNAVAILABLE,
    ATTEST_VIOLATION,
    ATTESTATION_COLUMNS,
    DAILY_COLUMNS,
    FINDING_BREAK,
    FINDING_COLUMNS,
    FINDING_GAP,
    FINDING_GRANT,
    GAP_TOKEN,
    GENERATION_TIME_SCOPE,
    GENESIS_TOKEN,
    NOTE_NO_FINDINGS,
    RUN_COLUMNS,
    SECTION_ATTESTATION,
    SECTION_DAILY,
    SECTION_FINDINGS,
    SECTION_RUNS,
    build_audit_integrity_sections,
)
from app.engines.reports.payloads import ReportSection
from app.engines.reports.redaction import RedactionViolationError, enforce_redaction
from app.models import Base
from app.models.audit import (
    AuditChainVerificationRun,
    ChainVerificationOutcome,
    GrantCheckOutcome,
)
from app.models.reports import ReportKind
from app.services.audit.grants import GrantCheckResult

_GOLDEN = Path(__file__).resolve().parent / "golden" / "audit_integrity_golden.json"

_PERIOD_START = datetime(2026, 7, 1, tzinfo=UTC)
_PERIOD_END = datetime(2026, 7, 8, tzinfo=UTC)
_GENERATED_AT = datetime(2026, 7, 8, 0, 5, tzinfo=UTC)

# Deterministic chain-entry ids and watermark digest PRESENTATIONS (hex SHA-256
# derived at runtime — these are tamper-evidence values, not secrets).
_E1 = uuid.UUID("00000000-0000-0000-0000-00000000e001")
_E2 = uuid.UUID("00000000-0000-0000-0000-00000000e002")
_E3 = uuid.UUID("00000000-0000-0000-0000-00000000e003")
_H1 = hashlib.sha256(b"watermark-1").hexdigest()
_H2 = hashlib.sha256(b"watermark-2").hexdigest()
_H3 = hashlib.sha256(b"watermark-3").hexdigest()


@pytest.fixture()
async def session(tmp_path: Path) -> AsyncIterator[AsyncSession]:
    """File-backed SQLite schema + one AsyncSession (T1 harness pattern)."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'audit_integrity.sqlite'}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db_session:
        yield db_session
    await engine.dispose()


def _vrun(
    run_id: uuid.UUID,
    started_at: datetime,
    *,
    outcome: str = ChainVerificationOutcome.CLEAN.value,
    entries_checked: int = 0,
    range_from: uuid.UUID | None = None,
    range_to: uuid.UUID | None = None,
    cp_before: str | None = None,
    cp_after: str | None = None,
    grant: str = GrantCheckOutcome.CLEAN.value,
) -> AuditChainVerificationRun:
    return AuditChainVerificationRun(
        id=run_id,
        started_at=started_at,
        finished_at=started_at + timedelta(minutes=1),
        outcome=outcome,
        entries_checked=entries_checked,
        range_from_entry_id=range_from,
        range_to_entry_id=range_to,
        checkpoint_before_hash=cp_before,
        checkpoint_after_hash=cp_after,
        grant_check_outcome=grant,
    )


def _scenario() -> list[AuditChainVerificationRun]:
    """Six runs over the 7-day period; day 3 (2026-07-03) has NO run (the gap).

    Day 5 is a chain BREAK day; day 6 carries a daily grant VIOLATION.
    """
    day = lambda d, h=1: datetime(2026, 7, d, h, 0, tzinfo=UTC)  # noqa: E731
    return [
        _vrun(
            uuid.UUID("00000000-0000-0000-0000-00000000ab01"),
            day(1),
            entries_checked=4,
            range_from=None,  # first run: walked from genesis
            range_to=_E1,
            cp_before=None,
            cp_after=_H1,
        ),
        _vrun(
            uuid.UUID("00000000-0000-0000-0000-00000000ab02"),
            day(2),
            entries_checked=2,
            range_from=_E1,
            range_to=_E2,
            cp_before=_H1,
            cp_after=_H2,
        ),
        # day 3: MISSING (the gap → finding)
        _vrun(
            uuid.UUID("00000000-0000-0000-0000-00000000ab04"),
            day(4),
            entries_checked=0,
            range_from=_E2,
            range_to=_E2,
            cp_before=_H2,
            cp_after=_H2,
        ),
        _vrun(
            uuid.UUID("00000000-0000-0000-0000-00000000ab05"),
            day(5),
            outcome=ChainVerificationOutcome.BREAK.value,
            entries_checked=1,
            range_from=_E2,
            range_to=_E2,
            cp_before=_H2,
            cp_after=_H2,  # a break never advances the watermark
        ),
        _vrun(
            uuid.UUID("00000000-0000-0000-0000-00000000ab06"),
            day(6),
            entries_checked=3,
            range_from=_E2,
            range_to=_E3,
            cp_before=_H2,
            cp_after=_H3,
            grant=GrantCheckOutcome.VIOLATION.value,
        ),
        _vrun(
            uuid.UUID("00000000-0000-0000-0000-00000000ab07"),
            day(7),
            entries_checked=0,
            range_from=_E3,
            range_to=_E3,
            cp_before=_H3,
            cp_after=_H3,
        ),
    ]


async def _seed(session: AsyncSession, runs: list[AuditChainVerificationRun]) -> None:
    session.add_all(runs)
    await session.commit()


def _by_title(sections: tuple[ReportSection, ...], title: str) -> ReportSection:
    return next(section for section in sections if section.title == title)


# ---------------------------------------------------------------------------
# Sections: runs, daily outcomes, findings
# ---------------------------------------------------------------------------


async def test_sections_shape_and_run_rows(session: AsyncSession) -> None:
    """Four sections with pinned titles/columns (golden + W4-T3 ride these)."""
    await _seed(session, _scenario())

    sections, _ = await build_audit_integrity_sections(
        session, period_start=_PERIOD_START, period_end=_PERIOD_END, generated_at=_GENERATED_AT
    )

    assert [s.title for s in sections] == [
        SECTION_RUNS,
        SECTION_DAILY,
        SECTION_FINDINGS,
        SECTION_ATTESTATION,
    ]
    runs_section = _by_title(sections, SECTION_RUNS)
    assert runs_section.columns == RUN_COLUMNS
    assert len(runs_section.rows) == 6
    first = runs_section.rows[0]
    # Genesis lower bound token, verified head id, digest presentation, grant.
    assert first[2] == ChainVerificationOutcome.CLEAN.value
    assert first[3] == "4"
    assert first[4] == GENESIS_TOKEN
    assert first[5] == str(_E1)
    assert first[6] == "none"  # no checkpoint existed before the first run
    assert first[7] == _H1
    assert first[8] == GrantCheckOutcome.CLEAN.value
    assert _by_title(sections, SECTION_DAILY).columns == DAILY_COLUMNS
    assert _by_title(sections, SECTION_FINDINGS).columns == FINDING_COLUMNS
    assert _by_title(sections, SECTION_ATTESTATION).columns == ATTESTATION_COLUMNS


async def test_daily_outcomes_render_gap_break_and_grant_violation(
    session: AsyncSession,
) -> None:
    """One row per UTC day; the missing day is an explicit gap, never a blank."""
    await _seed(session, _scenario())

    sections, _ = await build_audit_integrity_sections(
        session, period_start=_PERIOD_START, period_end=_PERIOD_END, generated_at=_GENERATED_AT
    )

    daily = _by_title(sections, SECTION_DAILY)
    assert len(daily.rows) == 7  # every UTC day of the period, gaps included
    by_date = {row[0]: row for row in daily.rows}
    assert by_date["2026-07-03"] == ("2026-07-03", "0", GAP_TOKEN, GAP_TOKEN)
    assert by_date["2026-07-05"][2] == ChainVerificationOutcome.BREAK.value
    assert by_date["2026-07-06"][3] == GrantCheckOutcome.VIOLATION.value
    assert by_date["2026-07-01"][2] == ChainVerificationOutcome.CLEAN.value


async def test_missing_day_break_day_and_grant_day_are_findings(session: AsyncSession) -> None:
    """Gaps ARE findings (spec requirement 2), as are break/grant days."""
    await _seed(session, _scenario())

    sections, notes = await build_audit_integrity_sections(
        session, period_start=_PERIOD_START, period_end=_PERIOD_END, generated_at=_GENERATED_AT
    )

    findings = _by_title(sections, SECTION_FINDINGS).rows
    kinds_and_scopes = [(row[0], row[1]) for row in findings]
    assert (FINDING_GAP, "2026-07-03") in kinds_and_scopes
    assert (FINDING_BREAK, "2026-07-05") in kinds_and_scopes
    assert (FINDING_GRANT, "2026-07-06") in kinds_and_scopes
    assert len(findings) == 3
    assert NOTE_NO_FINDINGS not in notes


async def test_clean_period_has_empty_findings_and_the_explicit_note(
    session: AsyncSession,
) -> None:
    """A fully-clean, fully-covered period renders zero findings + the note."""
    runs = [
        _vrun(
            uuid.uuid4(),
            datetime(2026, 7, d, 1, 0, tzinfo=UTC),
            entries_checked=1,
            range_from=_E1,
            range_to=_E1,
            cp_before=_H1,
            cp_after=_H1,
        )
        for d in range(1, 8)
    ]
    await _seed(session, runs)

    sections, notes = await build_audit_integrity_sections(
        session, period_start=_PERIOD_START, period_end=_PERIOD_END, generated_at=_GENERATED_AT
    )

    assert _by_title(sections, SECTION_FINDINGS).rows == ()
    assert NOTE_NO_FINDINGS in notes


# ---------------------------------------------------------------------------
# Live grant attestation (spec requirement 3)
# ---------------------------------------------------------------------------


async def test_attestation_is_honest_unavailable_on_sqlite(session: AsyncSession) -> None:
    """No grant catalog on SQLite → the explicit unavailable token, never clean."""
    await _seed(session, _scenario())

    sections, _ = await build_audit_integrity_sections(
        session, period_start=_PERIOD_START, period_end=_PERIOD_END, generated_at=_GENERATED_AT
    )

    attestation = dict(_by_title(sections, SECTION_ATTESTATION).rows)
    assert attestation["Attestation"] == ATTEST_UNAVAILABLE
    assert attestation["Attested at (UTC)"] == _GENERATED_AT.isoformat()
    assert attestation["UPDATE/DELETE grants found"] == GrantCheckOutcome.UNAVAILABLE.value
    # The backend-unavailability is NOT a generation-time grant violation.
    findings = _by_title(sections, SECTION_FINDINGS).rows
    assert (FINDING_GRANT, GENERATION_TIME_SCOPE) not in {(r[0], r[1]) for r in findings}


async def test_live_attestation_violation_adds_generation_time_finding(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A live catalog violation renders VIOLATION + the generation-time finding."""

    async def _violation(_session: AsyncSession) -> GrantCheckResult:
        return GrantCheckResult(
            outcome=GrantCheckOutcome.VIOLATION.value,
            grants=(("audit_log", "evil_role", "UPDATE"),),
        )

    monkeypatch.setattr(audit_integrity_module, "check_audit_log_grants", _violation)

    sections, _ = await build_audit_integrity_sections(
        session, period_start=_PERIOD_START, period_end=_PERIOD_END, generated_at=_GENERATED_AT
    )

    attestation = dict(_by_title(sections, SECTION_ATTESTATION).rows)
    assert attestation["Attestation"] == ATTEST_VIOLATION
    assert attestation["UPDATE/DELETE grants found"] == "1"
    assert attestation["Grants"] == "audit_log: evil_role (UPDATE)"
    findings = _by_title(sections, SECTION_FINDINGS).rows
    assert (FINDING_GRANT, GENERATION_TIME_SCOPE) in {(r[0], r[1]) for r in findings}


async def test_attestation_runs_live_on_every_generation_never_cached(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The catalog check executes per build — a cached result could let a
    transient UPDATE grant slip a period (the named W3-T5 risk)."""
    calls = 0

    async def _counting(_session: AsyncSession) -> GrantCheckResult:
        nonlocal calls
        calls += 1
        return GrantCheckResult(outcome=GrantCheckOutcome.CLEAN.value, grants=())

    monkeypatch.setattr(audit_integrity_module, "check_audit_log_grants", _counting)

    for _ in range(2):
        sections, _ = await build_audit_integrity_sections(
            session,
            period_start=_PERIOD_START,
            period_end=_PERIOD_END,
            generated_at=_GENERATED_AT,
        )
        attestation = dict(_by_title(sections, SECTION_ATTESTATION).rows)
        assert attestation["Attestation"] == ATTEST_CLEAN

    assert calls == 2


# ---------------------------------------------------------------------------
# Sibling bug-class sweeps (W3-T1 findings)
# ---------------------------------------------------------------------------


async def test_naive_period_inputs_are_pinned_as_utc(session: AsyncSession) -> None:
    """Naive datetimes must mean the SAME wall-clock period as aware-UTC ones."""
    await _seed(session, _scenario())

    aware_sections, _ = await build_audit_integrity_sections(
        session, period_start=_PERIOD_START, period_end=_PERIOD_END, generated_at=_GENERATED_AT
    )
    naive_sections, _ = await build_audit_integrity_sections(
        session,
        period_start=_PERIOD_START.replace(tzinfo=None),
        period_end=_PERIOD_END.replace(tzinfo=None),
        generated_at=_GENERATED_AT,
    )

    assert naive_sections == aware_sections


async def test_build_payload_dispatches_the_live_builder(session: AsyncSession) -> None:
    """kind=audit_integrity builds the real payload — the skeleton is gone."""
    await _seed(session, _scenario())

    payload = await build_payload(
        session,
        kind=ReportKind.AUDIT_INTEGRITY,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    assert payload.kind == "audit_integrity"
    assert payload.regime_tags == ("soc2:CC7.2",)
    titles = [s.title for s in payload.sections]
    assert SECTION_RUNS in titles
    assert SECTION_ATTESTATION in titles
    assert not any("skeleton" in note for note in payload.notes)


# ---------------------------------------------------------------------------
# Redaction: digests pass (requirement 4), planted secrets still fail closed
# ---------------------------------------------------------------------------


async def test_digest_bearing_payload_passes_the_redaction_choke_point(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Full 64-hex SHA-256 digests must NOT trip redaction (format-anchored
    patterns, deliberately no entropy detection — ADR-0053 §6 / alt 5)."""
    from app.engines.reports import render

    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.AUDIT_INTEGRITY,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    # The payload actually carries full-length digests (anti-vacuous).
    csv_texts = [cell for s in payload.sections for row in s.rows for cell in row]
    assert _H1 in csv_texts and _H3 in csv_texts

    artifacts = render_artifacts(payload)

    assert sorted(a.format.value for a in artifacts) == ["csv", "pdf"]
    assert _H1 in artifacts[0].content.decode("utf-8")


async def test_planted_pem_value_fails_closed(session: AsyncSession) -> None:
    """A PEM-formatted value in any cell aborts generation (fail closed)."""
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.AUDIT_INTEGRITY,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )
    # Assembled at runtime so secret scanners never see a literal PEM header.
    pem_value = "-----BEGIN " + "RSA PRIVATE " + "KEY-----"
    planted = payload.model_copy(
        update={
            "sections": (
                *payload.sections,
                ReportSection(title="Planted", columns=("Field",), rows=((pem_value,),)),
            )
        }
    )

    with pytest.raises(RedactionViolationError):
        enforce_redaction(planted)


def test_section_headers_and_tokens_clear_the_deny_class() -> None:
    """No pinned header may trip the deny-class name filter (fail-closed)."""
    from app.engines.reports.redaction import DENY_FIELD_NAME_TOKENS

    for columns in (RUN_COLUMNS, DAILY_COLUMNS, FINDING_COLUMNS, ATTESTATION_COLUMNS):
        for header in columns:
            lowered = header.casefold()
            assert not any(token in lowered for token in DENY_FIELD_NAME_TOKENS), header


# ---------------------------------------------------------------------------
# Golden CSV/PDF structure fixture (W4-T3 rides this file)
# ---------------------------------------------------------------------------


async def test_golden_csv_and_pdf_structure(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deterministic scenario renders EXACTLY the committed golden structure.

    CSV: parsed rows compare exactly (deterministic payload → deterministic
    bytes). PDF: structure-stable, not byte-golden (ADR-0053 §1) — the rendered
    HTML that WeasyPrint consumes must carry every golden section title and
    column header. W4-T3's conformance checks assert against the same fixture.
    """
    from app.engines.reports import render

    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.AUDIT_INTEGRITY,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))

    artifacts = render_artifacts(payload)
    csv_artifact = next(a for a in artifacts if a.format.value == "csv")
    parsed_rows = list(csv.reader(io.StringIO(csv_artifact.content.decode("utf-8"))))
    assert parsed_rows == golden["csv_rows"]

    html_source = render._jinja_env().get_template("report_base.html").render(payload=payload)
    for section in golden["pdf_structure"]["sections"]:
        assert f"<h2>{section['title']}</h2>" in html_source
        for column in section["columns"]:
            assert f"<th>{column}</th>" in html_source
    # The golden fixture carries digest PRESENTATIONS only — no secret-format
    # material may appear in it (the redaction posture, asserted on the text).
    golden_text = _GOLDEN.read_text(encoding="utf-8")
    assert "PRIVATE " + "KEY" not in golden_text
