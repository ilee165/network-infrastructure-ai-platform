"""Compliance posture builder (P4 W3-T3; ADR-0053 §7.2) — unit suite.

The posture report rolls the M4 compliance engine up from the PERSISTED
`compliance_runs`/`compliance_run_findings` history (populated by the daily
``reports.compliance_sweep`` beat task): pass/fail by policy, device, and
severity from the latest run in the period, plus a daily trend series in which
a day with no recorded run renders as an EXPLICIT gap — never interpolated.

Covered here (SQLite; every aggregation query re-asserts on real PostgreSQL in
``tests/pg/test_compliance_posture_pg.py``):

* latest-posture roll-ups come from the most recent run in the CLOSED-OPEN
  period, with engine/policy-pack version stamped per run;
* gap days carry the explicit gap token, never a fabricated zero;
* empty history renders the empty-history note and NO fabricated posture rows;
* F5 BIG-IP / VMware surface as out-of-scope (ADR-0050 §7.6 / ADR-0051 §3) —
  honestly uncovered, never passing;
* naive period inputs are pinned as UTC (the W3-T1 phantom-run-id class) and
  offset-aware stored timestamps bucket into the right UTC day;
* the payload passes the engine redaction choke point; headers clear the
  deny class;
* the golden CSV/PDF structure fixture for W4-T3's conformance checks.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.engines.reports import ENGINE_VERSION, build_payload, render_artifacts
from app.engines.reports.compliance_posture import (
    DEVICE_COLUMNS,
    GAP_TOKEN,
    NOTE_EMPTY_HISTORY,
    OUT_OF_SCOPE_COLUMNS,
    OUT_OF_SCOPE_VENDORS,
    POLICY_COLUMNS,
    RUN_COLUMNS,
    SECTION_BY_DEVICE,
    SECTION_BY_POLICY,
    SECTION_BY_SEVERITY,
    SECTION_OUT_OF_SCOPE,
    SECTION_RUNS,
    SECTION_TREND,
    SEVERITY_COLUMNS,
    TREND_COLUMNS,
    build_compliance_posture_sections,
)
from app.engines.reports.payloads import ReportSection
from app.models import Base, Device, DeviceStatus
from app.models.compliance_history import ComplianceRun, ComplianceRunFinding
from app.models.reports import ReportKind

_GOLDEN = Path(__file__).resolve().parent / "golden" / "compliance_posture_golden.json"

_PERIOD_START = datetime(2026, 7, 1, tzinfo=UTC)
_PERIOD_END = datetime(2026, 7, 8, tzinfo=UTC)
_GENERATED_AT = datetime(2026, 7, 8, 0, 5, tzinfo=UTC)

_CORE = uuid.UUID("00000000-0000-0000-0000-00000000d001")
_EDGE = uuid.UUID("00000000-0000-0000-0000-00000000d002")
_F5 = uuid.UUID("00000000-0000-0000-0000-00000000d0f5")
_VC = uuid.UUID("00000000-0000-0000-0000-00000000d0ec")
_RUN_A = uuid.UUID("00000000-0000-0000-0000-00000000aa01")
_RUN_B = uuid.UUID("00000000-0000-0000-0000-00000000bb01")
_RUN_C = uuid.UUID("00000000-0000-0000-0000-00000000cc01")

_POLICY = "baseline-security"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session(tmp_path: Path) -> AsyncIterator[AsyncSession]:
    """File-backed SQLite schema + one AsyncSession (T1 harness pattern)."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'compliance_posture.sqlite'}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db_session:
        yield db_session
    await engine.dispose()


def _device(device_id: uuid.UUID, hostname: str, mgmt_ip: str, vendor: str) -> Device:
    return Device(
        id=device_id,
        hostname=hostname,
        mgmt_ip=mgmt_ip,
        vendor_id=vendor,
        status=DeviceStatus.REACHABLE,
        site="hq",
    )


def _run(
    run_id: uuid.UUID,
    executed_at: datetime,
    trigger: str,
    policy_version: int,
    device_scope: list[str],
) -> ComplianceRun:
    return ComplianceRun(
        id=run_id,
        executed_at=executed_at,
        trigger=trigger,
        policy_id=_POLICY,
        policy_version=policy_version,
        device_scope=device_scope,
        engine_version=ENGINE_VERSION,
    )


def _finding(
    run_id: uuid.UUID, device_id: uuid.UUID, rule_id: str, status: str, severity: str
) -> ComplianceRunFinding:
    return ComplianceRunFinding(
        run_id=run_id,
        device_id=device_id,
        policy_id=_POLICY,
        rule_id=rule_id,
        status=status,
        severity=severity,
    )


def _scenario() -> list[Any]:
    """Deterministic history: runs on 07-01 and 07-03 (two), gaps elsewhere.

    The latest run in the period is RUN_C (07-03 05:00, policy pack v4):
    core-sw-01 → 1 pass / 1 violation; edge-sw-01 → 1 violation / 1 skipped.
    RUN_B (same day, 04:00, on_demand) exists to prove a day's posture comes
    from its most recent run, and that "Runs recorded" counts every run.
    """
    return [
        _device(_CORE, "core-sw-01", "10.0.0.1", "cisco_ios"),
        _device(_EDGE, "edge-sw-01", "10.0.0.2", "eos"),
        _device(_F5, "lb-01", "10.0.0.3", "f5_bigip"),
        _device(_VC, "vcenter-01", "10.0.0.4", "vmware"),
        _run(
            _RUN_A,
            datetime(2026, 7, 1, 4, 30, tzinfo=UTC),
            "sweep",
            3,
            [str(_CORE), str(_EDGE)],
        ),
        _finding(_RUN_A, _CORE, "rule-ssh", "pass", "violation"),
        _finding(_RUN_A, _CORE, "rule-telnet", "violation", "warn"),
        _finding(_RUN_A, _EDGE, "rule-ssh", "pass", "violation"),
        _finding(_RUN_A, _EDGE, "rule-banner", "skipped", "info"),
        _run(_RUN_B, datetime(2026, 7, 3, 4, 0, tzinfo=UTC), "on_demand", 4, [str(_CORE)]),
        _finding(_RUN_B, _CORE, "rule-ssh", "violation", "violation"),
        _run(
            _RUN_C,
            datetime(2026, 7, 3, 5, 0, tzinfo=UTC),
            "sweep",
            4,
            [str(_CORE), str(_EDGE)],
        ),
        _finding(_RUN_C, _CORE, "rule-ssh", "pass", "violation"),
        _finding(_RUN_C, _CORE, "rule-telnet", "violation", "warn"),
        _finding(_RUN_C, _EDGE, "rule-ssh", "violation", "violation"),
        _finding(_RUN_C, _EDGE, "rule-banner", "skipped", "info"),
    ]


async def _seed(session: AsyncSession, instances: list[Any]) -> None:
    session.add_all(instances)
    await session.commit()


def _section(sections: tuple[ReportSection, ...], title: str) -> ReportSection:
    return next(s for s in sections if s.title == title)


async def _build(
    session: AsyncSession,
    start: datetime = _PERIOD_START,
    end: datetime = _PERIOD_END,
) -> tuple[tuple[ReportSection, ...], tuple[str, ...]]:
    return await build_compliance_posture_sections(session, period_start=start, period_end=end)


# ---------------------------------------------------------------------------
# Section structure
# ---------------------------------------------------------------------------


async def test_sections_and_columns_are_stable(session: AsyncSession) -> None:
    """Six sections with pinned titles/columns (golden + W4-T3 ride these)."""
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    assert [s.title for s in sections] == [
        SECTION_RUNS,
        SECTION_BY_POLICY,
        SECTION_BY_DEVICE,
        SECTION_BY_SEVERITY,
        SECTION_TREND,
        SECTION_OUT_OF_SCOPE,
    ]
    assert _section(sections, SECTION_RUNS).columns == RUN_COLUMNS
    assert _section(sections, SECTION_BY_POLICY).columns == POLICY_COLUMNS
    assert _section(sections, SECTION_BY_DEVICE).columns == DEVICE_COLUMNS
    assert _section(sections, SECTION_BY_SEVERITY).columns == SEVERITY_COLUMNS
    assert _section(sections, SECTION_TREND).columns == TREND_COLUMNS
    assert _section(sections, SECTION_OUT_OF_SCOPE).columns == OUT_OF_SCOPE_COLUMNS


async def test_runs_section_stamps_engine_and_policy_versions(session: AsyncSession) -> None:
    """Requirement 2 (ADR-0053 §7.2): version provenance per persisted run."""
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    rows = _section(sections, SECTION_RUNS).rows
    assert [row[0] for row in rows] == [str(_RUN_A), str(_RUN_B), str(_RUN_C)]
    run_a = rows[0]
    assert run_a[1] == "2026-07-01T04:30:00+00:00"
    assert run_a[2] == "sweep"
    assert run_a[3] == _POLICY
    assert run_a[4] == "3"  # policy pack version stamped
    assert run_a[5] == ENGINE_VERSION  # engine version stamped
    assert run_a[6] == "2"  # devices in scope
    assert rows[1][2] == "on_demand"
    assert rows[2][4] == "4"


# ---------------------------------------------------------------------------
# Latest posture roll-ups (by policy / device / severity)
# ---------------------------------------------------------------------------


async def test_latest_posture_comes_from_most_recent_run_only(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    # RUN_C only: 1 pass + 1 violation (core), 1 violation + 1 skipped (edge).
    assert _section(sections, SECTION_BY_POLICY).rows == ((_POLICY, "1", "2", "1"),)
    assert _section(sections, SECTION_BY_DEVICE).rows == (
        ("core-sw-01", "cisco_ios", "1", "1", "0"),
        ("edge-sw-01", "eos", "0", "1", "1"),
    )


async def test_severity_rollup_covers_the_full_vocabulary(session: AsyncSession) -> None:
    """All three ADR-0018 severities render, in enum order, zeros measured."""
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    assert _section(sections, SECTION_BY_SEVERITY).rows == (
        ("info", "0", "0", "1"),
        ("warn", "0", "1", "0"),
        ("violation", "1", "1", "0"),
    )


async def test_finding_for_a_deleted_device_renders_opaque_reference(
    session: AsyncSession,
) -> None:
    ghost = uuid.UUID("00000000-0000-0000-0000-00000000dead")
    await _seed(
        session,
        [*_scenario(), _finding(_RUN_C, ghost, "rule-ssh", "violation", "warn")],
    )
    sections, _ = await _build(session)

    rows = _section(sections, SECTION_BY_DEVICE).rows
    assert (f"device:{ghost}", "none", "0", "1", "0") in rows


# ---------------------------------------------------------------------------
# Trend — gaps render as gaps, never interpolated
# ---------------------------------------------------------------------------


async def test_trend_has_one_row_per_utc_day_with_explicit_gaps(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, notes = await _build(session)

    trend = _section(sections, SECTION_TREND).rows
    assert [row[0] for row in trend] == [
        "2026-07-01",
        "2026-07-02",
        "2026-07-03",
        "2026-07-04",
        "2026-07-05",
        "2026-07-06",
        "2026-07-07",
    ]
    # 07-01: one run, RUN_A posture (2 pass / 1 violation / 1 skipped).
    assert trend[0] == ("2026-07-01", "1", "2", "2", "1", "1")
    # 07-03: TWO runs recorded; posture from the day's most recent (RUN_C).
    assert trend[2] == ("2026-07-03", "2", "2", "1", "2", "1")
    # Gap days: zero runs is measured; posture is UNKNOWN — the gap token,
    # never a fabricated zero or a carried-forward value.
    for gap_day in (trend[1], *trend[3:]):
        assert gap_day[1] == "0"
        assert gap_day[2:] == (GAP_TOKEN, GAP_TOKEN, GAP_TOKEN, GAP_TOKEN)
    assert any("never interpolated" in note for note in notes)


async def test_gap_days_never_render_zero_posture_counts(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, _ = await _build(session)

    for row in _section(sections, SECTION_TREND).rows:
        if row[1] == "0":  # no run recorded that day
            assert "0" not in row[2:], f"gap day {row[0]} fabricated a zero count"


async def test_offset_aware_timestamp_buckets_into_its_utc_day(session: AsyncSession) -> None:
    """03:00+05:30 on 07-02 is 21:30 UTC on 07-01 — trend buckets by UTC day."""
    offset = timezone(timedelta(hours=5, minutes=30))
    await _seed(
        session,
        [_run(_RUN_A, datetime(2026, 7, 2, 3, 0, tzinfo=offset), "sweep", 3, [])],
    )
    sections, _ = await _build(session)

    trend = _section(sections, SECTION_TREND).rows
    assert trend[0][:2] == ("2026-07-01", "1")
    assert trend[1][:2] == ("2026-07-02", "0")


async def test_naive_period_inputs_are_pinned_as_utc(session: AsyncSession) -> None:
    """W3 sibling bug class: naive bounds mean the same wall-clock UTC period."""
    await _seed(session, _scenario())
    aware_sections, aware_notes = await _build(session)
    naive_sections, naive_notes = await _build(session, datetime(2026, 7, 1), datetime(2026, 7, 8))

    assert naive_sections == aware_sections
    assert naive_notes == aware_notes


# ---------------------------------------------------------------------------
# Empty history — nothing fabricated
# ---------------------------------------------------------------------------


async def test_empty_history_renders_note_and_no_fabricated_posture(
    session: AsyncSession,
) -> None:
    await _seed(
        session,
        [
            _device(_F5, "lb-01", "10.0.0.3", "f5_bigip"),
            _device(_VC, "vcenter-01", "10.0.0.4", "vmware"),
        ],
    )
    sections, notes = await _build(session)

    assert notes[0] == NOTE_EMPTY_HISTORY
    assert _section(sections, SECTION_RUNS).rows == ()
    assert _section(sections, SECTION_BY_POLICY).rows == ()
    assert _section(sections, SECTION_BY_DEVICE).rows == ()
    # No latest run exists -> severity rows would be a fabricated measurement.
    assert _section(sections, SECTION_BY_SEVERITY).rows == ()
    trend = _section(sections, SECTION_TREND).rows
    assert len(trend) == 7
    assert all(row[2:] == (GAP_TOKEN,) * 4 for row in trend)
    # The out-of-scope posture is inventory-driven and still surfaces.
    assert _section(sections, SECTION_OUT_OF_SCOPE).rows != ()


# ---------------------------------------------------------------------------
# Out-of-scope vendors — honest, never passing
# ---------------------------------------------------------------------------


async def test_out_of_scope_vendors_surface_and_never_pass(session: AsyncSession) -> None:
    await _seed(session, _scenario())
    sections, notes = await _build(session)

    rows = _section(sections, SECTION_OUT_OF_SCOPE).rows
    assert [row[0] for row in rows] == [vendor for vendor, _ in OUT_OF_SCOPE_VENDORS]
    by_vendor = {row[0]: row for row in rows}
    assert by_vendor["f5_bigip"][1] == "1"
    assert by_vendor["vmware"][1] == "1"
    for row in rows:
        assert "out-of-scope" in row[2]
        assert "pass" not in row[2]
    # Their devices carry NO posture rows — uncovered, not silently passing.
    device_labels = {row[0] for row in _section(sections, SECTION_BY_DEVICE).rows}
    assert "lb-01" not in device_labels
    assert "vcenter-01" not in device_labels
    assert any("never" in note and "passing" in note for note in notes)


async def test_out_of_scope_rows_render_even_with_no_such_devices(
    session: AsyncSession,
) -> None:
    """The named deferral is documented posture, not contingent on inventory."""
    sections, _ = await _build(session)

    rows = _section(sections, SECTION_OUT_OF_SCOPE).rows
    assert [row[:2] for row in rows] == [("f5_bigip", "0"), ("vmware", "0")]


# ---------------------------------------------------------------------------
# Engine wiring + redaction sanity
# ---------------------------------------------------------------------------


async def test_build_payload_wires_compliance_posture_off_the_skeleton(
    session: AsyncSession,
) -> None:
    await _seed(session, _scenario())

    payload = await build_payload(
        session,
        kind=ReportKind.COMPLIANCE_POSTURE,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    assert payload.kind == "compliance_posture"
    assert payload.regime_tags == ("soc2:CC7.1", "soc2:CC4.1")
    titles = [s.title for s in payload.sections]
    assert SECTION_TREND in titles
    assert not any("skeleton" in note for note in payload.notes)


async def test_posture_payload_passes_the_redaction_choke_point(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real payload renders through the SINGLE path (redaction runs first)."""
    from app.engines.reports import render

    monkeypatch.setattr(render, "_render_pdf", lambda payload: b"%PDF-1.7 stub")
    await _seed(session, _scenario())
    payload = await build_payload(
        session,
        kind=ReportKind.COMPLIANCE_POSTURE,
        period_start=_PERIOD_START,
        period_end=_PERIOD_END,
        generated_at=_GENERATED_AT,
    )

    artifacts = render_artifacts(payload)

    assert sorted(a.format.value for a in artifacts) == ["csv", "pdf"]


def test_section_headers_and_tokens_clear_the_deny_class() -> None:
    """No pinned header/token may trip the deny-class name filter (fail-closed)."""
    from app.engines.reports.redaction import DENY_FIELD_NAME_TOKENS

    for columns in (
        RUN_COLUMNS,
        POLICY_COLUMNS,
        DEVICE_COLUMNS,
        SEVERITY_COLUMNS,
        TREND_COLUMNS,
        OUT_OF_SCOPE_COLUMNS,
    ):
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
        kind=ReportKind.COMPLIANCE_POSTURE,
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
    # The golden fixture itself must carry zero evidence excerpts: the history
    # tables have no excerpt column, so no config-flavored text can appear.
    assert "interface" not in _GOLDEN.read_text(encoding="utf-8")
