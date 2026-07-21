"""Independent helpers for the P4-W4 report-conformance eval corpus.

The corpus consumes the four existing W3 golden CSV row sets, reconstructs
fixed :class:`ReportPayload` objects, and keeps its completeness oracle in a
small, separately authored manifest.  The artifact scanner deliberately owns
its own two planted-control signatures and imports no production redaction
tokens or patterns.
"""

from __future__ import annotations

import csv
import io
import json
import re
import shlex
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

import yaml

from app.engines.reports.payloads import ReportPayload, ReportSection

REQUIRED_NATIVE_PACKAGES: Final[tuple[str, ...]] = (
    "libpango-1.0-0",
    "libpangoft2-1.0-0",
    "libharfbuzz0b",
    "libharfbuzz-subset0",
    "fontconfig",
    "fonts-dejavu-core",
)
AUTHORIZATION_FINDING: Final = "deny-header:authorization"
PEM_FINDING: Final = "value-format:pem-private-key"

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_MANIFEST = Path(__file__).resolve().parent / "fixtures" / "report_conformance_cases.json"
_EXPECTED_KINDS = ("change", "compliance_posture", "access_review", "audit_integrity")
_EXPECTED_ANCHOR_NAMES = {
    "change": ("change-request-lifecycle", "change-request-transition-sequences"),
    "compliance_posture": ("daily-posture-days-and-gaps",),
    "access_review": ("break-glass-event-keys",),
    "audit_integrity": (
        "daily-integrity-days-and-gaps",
        "generation-time-attestation-fields",
        "integrity-gap-finding",
    ),
}
_METADATA_KEYS = (
    "report",
    "kind",
    "period_start",
    "period_end",
    "generated_at",
    "regime_tags",
)
_PDF_ARTIFACTS = frozenset({"\u00ad", "\u200b", "\u200c", "\u200d", "\ufeff"})
_NATIVE_LIBRARY_NAMES = (
    "libgobject",
    "gobject",
    "libpango",
    "pango",
    "libharfbuzz",
    "harfbuzz",
)


class CompletenessError(AssertionError):
    """A required independent completeness anchor was absent or reordered."""


@dataclass(frozen=True)
class CompletenessAnchor:
    name: str
    section: str
    columns: tuple[str, ...]
    required_rows: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class ReportConformanceCase:
    kind: str
    payload: ReportPayload
    golden_csv_rows: tuple[tuple[str, ...], ...]
    anchors: tuple[CompletenessAnchor, ...]


def parse_csv_bytes(content: bytes) -> tuple[tuple[str, ...], ...]:
    """Parse emitted CSV exactly as an auditor-facing CSV stream."""
    if not isinstance(content, bytes):
        raise TypeError("CSV artifact must be bytes")
    stream = io.StringIO(content.decode("utf-8", errors="strict"), newline="")
    return tuple(tuple(row) for row in csv.reader(stream))


def _golden_rows(raw_rows: Any, *, path: Path) -> tuple[tuple[str, ...], ...]:
    if not isinstance(raw_rows, list) or not all(isinstance(row, list) for row in raw_rows):
        raise ValueError(f"{path}: csv_rows must be a list of rows")
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    for raw_row in raw_rows:
        if not all(isinstance(cell, str) for cell in raw_row):
            raise ValueError(f"{path}: every golden CSV cell must be a string")
        writer.writerow(raw_row)
    return parse_csv_bytes(buffer.getvalue().encode("utf-8"))


def _payload_from_rows(rows: tuple[tuple[str, ...], ...], *, path: Path) -> ReportPayload:
    if len(rows) < len(_METADATA_KEYS):
        raise ValueError(f"{path}: incomplete CSV metadata")
    metadata: dict[str, str] = {}
    for index, key in enumerate(_METADATA_KEYS):
        row = rows[index]
        if len(row) != 2 or row[0] != key:
            raise ValueError(f"{path}: expected metadata row {key!r} at index {index}")
        metadata[key] = row[1]

    sections: list[ReportSection] = []
    notes: list[str] = []
    cursor = len(_METADATA_KEYS)
    while cursor < len(rows):
        row = rows[cursor]
        if not row:
            cursor += 1
            continue
        if row[0] == "note":
            if len(row) != 2:
                raise ValueError(f"{path}: malformed note row at index {cursor}")
            notes.append(row[1])
            cursor += 1
            continue
        if len(row) != 1:
            raise ValueError(f"{path}: malformed section title at index {cursor}")
        title = row[0]
        cursor += 1
        if cursor >= len(rows) or not rows[cursor]:
            raise ValueError(f"{path}: section {title!r} has no column row")
        columns = rows[cursor]
        cursor += 1
        data_rows: list[tuple[str, ...]] = []
        while cursor < len(rows) and rows[cursor]:
            data_row = rows[cursor]
            if data_row[0] == "note":
                raise ValueError(f"{path}: section {title!r} was not terminated before notes")
            if len(data_row) != len(columns):
                raise ValueError(
                    f"{path}: section {title!r} row {cursor} has {len(data_row)} cells; "
                    f"expected {len(columns)}"
                )
            data_rows.append(data_row)
            cursor += 1
        sections.append(ReportSection(title=title, columns=columns, rows=tuple(data_rows)))

    return ReportPayload(
        kind=metadata["kind"],
        title=metadata["report"],
        period_start=datetime.fromisoformat(metadata["period_start"]),
        period_end=datetime.fromisoformat(metadata["period_end"]),
        generated_at=datetime.fromisoformat(metadata["generated_at"]),
        regime_tags=tuple(metadata["regime_tags"].split()),
        sections=tuple(sections),
        notes=tuple(notes),
    )


def _load_golden(path: Path) -> tuple[ReportPayload, tuple[tuple[str, ...], ...]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: golden root must be an object")
    rows = _golden_rows(raw.get("csv_rows"), path=path)
    payload = _payload_from_rows(rows, path=path)

    pdf_structure = raw.get("pdf_structure")
    if not isinstance(pdf_structure, dict) or not isinstance(pdf_structure.get("sections"), list):
        raise ValueError(f"{path}: missing pdf_structure.sections")
    observed_structure = tuple((section.title, section.columns) for section in payload.sections)
    expected_structure = tuple(
        (str(section["title"]), tuple(str(column) for column in section["columns"]))
        for section in pdf_structure["sections"]
    )
    if observed_structure != expected_structure:
        raise ValueError(f"{path}: CSV and PDF section structures disagree")
    return payload, rows


def _anchor(raw: Any, *, kind: str) -> CompletenessAnchor:
    if not isinstance(raw, dict):
        raise ValueError(f"{kind}: anchor must be an object")
    try:
        name = raw["name"]
        section = raw["section"]
        columns = raw["columns"]
        required_rows = raw["required_rows"]
    except KeyError as exc:
        raise ValueError(f"{kind}: incomplete anchor") from exc
    if not isinstance(name, str) or not isinstance(section, str):
        raise ValueError(f"{kind}: anchor name/section must be strings")
    if not isinstance(columns, list) or not all(isinstance(column, str) for column in columns):
        raise ValueError(f"{kind}/{name}: columns must be strings")
    if not isinstance(required_rows, list):
        raise ValueError(f"{kind}/{name}: required_rows must be a list")
    parsed_rows: list[tuple[str, ...]] = []
    for row in required_rows:
        if (
            not isinstance(row, list)
            or len(row) != len(columns)
            or not all(isinstance(cell, str) for cell in row)
        ):
            raise ValueError(f"{kind}/{name}: malformed required row")
        parsed_rows.append(tuple(row))
    return CompletenessAnchor(
        name=name,
        section=section,
        columns=tuple(columns),
        required_rows=tuple(parsed_rows),
    )


def load_report_conformance_cases() -> tuple[ReportConformanceCase, ...]:
    raw = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("unsupported report-conformance manifest schema")
    raw_cases = raw.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("report-conformance cases must be a list")

    cases: list[ReportConformanceCase] = []
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise ValueError("report-conformance case must be an object")
        kind = raw_case.get("kind")
        golden = raw_case.get("golden")
        anchors = raw_case.get("anchors")
        if (
            not isinstance(kind, str)
            or not isinstance(golden, str)
            or not isinstance(anchors, list)
        ):
            raise ValueError("report-conformance case is incomplete")
        golden_path = (_BACKEND_ROOT / golden).resolve()
        if not golden_path.is_relative_to(_BACKEND_ROOT):
            raise ValueError(f"{kind}: golden path escapes backend root")
        payload, rows = _load_golden(golden_path)
        if payload.kind != kind:
            raise ValueError(f"{kind}: golden payload kind is {payload.kind!r}")
        cases.append(
            ReportConformanceCase(
                kind=kind,
                payload=payload,
                golden_csv_rows=rows,
                anchors=tuple(_anchor(item, kind=kind) for item in anchors),
            )
        )
    kinds = tuple(case.kind for case in cases)
    if kinds != _EXPECTED_KINDS:
        raise ValueError(f"manifest kinds/order drifted: {kinds!r}")
    for case in cases:
        anchor_names = tuple(anchor.name for anchor in case.anchors)
        expected_anchor_names = _EXPECTED_ANCHOR_NAMES[case.kind]
        if anchor_names != expected_anchor_names:
            raise ValueError(
                f"{case.kind}: anchor names/order drifted: {anchor_names!r}; "
                f"expected {expected_anchor_names!r}"
            )
    return tuple(cases)


def case_by_kind(kind: str) -> ReportConformanceCase:
    matches = [case for case in load_report_conformance_cases() if case.kind == kind]
    if len(matches) != 1:
        raise KeyError(f"expected one report-conformance case for {kind!r}")
    return matches[0]


def _section(payload: ReportPayload, title: str) -> ReportSection:
    matches = [section for section in payload.sections if section.title == title]
    if len(matches) != 1:
        raise CompletenessError(f"expected exactly one section {title!r}")
    return matches[0]


def _project(section: ReportSection, columns: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    try:
        indexes = tuple(section.columns.index(column) for column in columns)
    except ValueError as exc:
        raise CompletenessError(
            f"section {section.title!r} is missing required columns {columns!r}"
        ) from exc
    return tuple(tuple(row[index] for index in indexes) for row in section.rows)


def validate_completeness(case: ReportConformanceCase, payload: ReportPayload) -> None:
    """Require each independently declared projection exactly, including order."""
    for anchor in case.anchors:
        observed = _project(_section(payload, anchor.section), anchor.columns)
        if observed != anchor.required_rows:
            raise CompletenessError(
                f"{case.kind}/{anchor.name}: completeness projection mismatch; "
                f"expected {anchor.required_rows!r}, observed {observed!r}"
            )
    if case.kind == "audit_integrity":
        attestation = _section(payload, "Append-only grant attestation (generation time)")
        fields = {row[0]: row[1] for row in _project(attestation, ("Field", "Value"))}
        expected_timestamp = payload.generated_at.isoformat()
        if fields.get("Attested at (UTC)") != expected_timestamp:
            raise CompletenessError(
                "audit_integrity/generation-time-attestation-fields: "
                "Attested at (UTC) must equal payload.generated_at.isoformat()"
            )


def remove_required_observed_row(
    case: ReportConformanceCase, anchor_index: int, row_index: int
) -> ReportPayload:
    """Delete one exact projected payload row without weakening the oracle."""
    anchor = case.anchors[anchor_index]
    section = _section(case.payload, anchor.section)
    projected = _project(section, anchor.columns)
    if projected != anchor.required_rows:
        raise CompletenessError(
            f"{case.kind}/{anchor.name}: mutation precondition projection mismatch"
        )
    if row_index < 0 or row_index >= len(projected):
        raise IndexError(f"{case.kind}/{anchor.name}: mutation row index {row_index} is invalid")
    target_index = row_index
    rows = section.rows[:target_index] + section.rows[target_index + 1 :]
    mutated_section = section.model_copy(update={"rows": rows})
    sections = tuple(
        mutated_section if candidate is section else candidate
        for candidate in case.payload.sections
    )
    return case.payload.model_copy(update={"sections": sections})


def _canonical_pdf_text(value: str) -> str:
    return "".join(
        character
        for character in value
        if character not in _PDF_ARTIFACTS and not character.isspace()
    )


def _extract_pdf_text(content: bytes) -> str:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(content))
    return "\n".join(page.extract_text() or "" for page in reader.pages)


def _pdf_units(payload: ReportPayload) -> tuple[str, ...]:
    units: list[str] = [
        payload.title,
        f"Regime tags: {', '.join(payload.regime_tags)}",
        f"Report kind{payload.kind}",
        f"Period start (UTC){payload.period_start.isoformat()}",
        f"Period end (UTC){payload.period_end.isoformat()}",
        f"Generated at (UTC){payload.generated_at.isoformat()}",
    ]
    for section in payload.sections:
        units.append(section.title)
        units.append("".join(section.columns))
        units.extend("".join(row) for row in section.rows)
    units.extend(payload.notes)
    return tuple(units)


def assert_pdf_extracted_text_semantics(extracted_text: str, payload: ReportPayload) -> None:
    """Assert every visible logical unit in monotonic extracted-text order.

    Whitespace is the only layout-dependent normalization: pypdf may insert it
    inside wrapped words/digests or omit it between adjacent table cells. Soft
    hyphens and zero-width artifacts are also removed. Punctuation, case, and
    content remain exact. Whole logical rows avoid false matches on short,
    repeated cells while tolerating repeated table headers at page breaks.
    """
    observed = _canonical_pdf_text(extracted_text)
    cursor = 0
    for unit in _pdf_units(payload):
        expected = _canonical_pdf_text(unit)
        if not expected:
            continue
        position = observed.find(expected, cursor)
        if position < 0:
            raise AssertionError(
                f"PDF semantic unit missing/out of order after cursor {cursor}: {unit!r}"
            )
        cursor = position + len(expected)


def assert_pdf_semantics(content: bytes, payload: ReportPayload) -> None:
    """Extract a PDF and assert every visible logical unit in exact order."""
    assert_pdf_extracted_text_semantics(_extract_pdf_text(content), payload)


def _pem_value() -> str:
    begin = "-----BEGIN " + "TEST PRIVATE " + "KEY-----"
    end = "-----END " + "TEST PRIVATE " + "KEY-----"
    return f"{begin}\nT3PLANTEDCONTROLPAYLOAD\n{end}"


def plant_report_secrets(payload: ReportPayload, plant: str) -> ReportPayload:
    if plant not in {"authorization", "pem", "both"}:
        raise ValueError(f"unsupported report-conformance plant: {plant!r}")
    first = payload.sections[0]
    columns = list(first.columns)
    rows = [list(row) for row in first.rows]
    if plant in {"authorization", "both"}:
        columns[0] = "Authorization"
    if plant in {"pem", "both"}:
        if not rows or len(rows[0]) < 2:
            raise ValueError("first report section has no [0][1] plant cell")
        rows[0][1] = _pem_value()
    planted = first.model_copy(
        update={"columns": tuple(columns), "rows": tuple(tuple(row) for row in rows)}
    )
    return payload.model_copy(update={"sections": (planted, *payload.sections[1:])})


def scan_artifact_bytes(artifact: bytes) -> frozenset[str]:
    """Scan only emitted bytes using independent planted-control signatures."""
    if not isinstance(artifact, bytes):
        raise TypeError("artifact scanner accepts bytes only")
    text = (
        _extract_pdf_text(artifact) if artifact.startswith(b"%PDF-") else artifact.decode("utf-8")
    )
    compact = _canonical_pdf_text(text)
    findings: set[str] = set()
    if "authorization" in compact.casefold():
        findings.add(AUTHORIZATION_FINDING)
    pem = re.compile(
        r"-----BEGIN[A-Z0-9]*PRIVATEKEY-----.*?-----END[A-Z0-9]*PRIVATEKEY-----",
        re.DOTALL,
    )
    if pem.search(compact.upper()):
        findings.add(PEM_FINDING)
    return frozenset(findings)


def is_pdf_native_runtime_unavailable(exc: BaseException) -> bool:
    """Recognize only missing WeasyPrint itself or its named native libraries."""
    if isinstance(exc, ModuleNotFoundError):
        return exc.name == "weasyprint"
    if not isinstance(exc, OSError):
        return False
    message = str(exc).casefold()
    load_failure = "cannot load library" in message or "no library called" in message
    return load_failure and any(name in message for name in _NATIVE_LIBRARY_NAMES)


def _step(steps: list[Any], name: str) -> tuple[int, dict[str, Any]]:
    matches = [
        (index, candidate)
        for index, candidate in enumerate(steps)
        if isinstance(candidate, dict) and candidate.get("name") == name
    ]
    assert len(matches) == 1, f"expected exactly one {name!r} step"
    return matches[0]


def _executable_commands(run: str) -> tuple[tuple[str, ...], ...]:
    logical_lines: list[str] = []
    pending = ""
    for raw_line in run.splitlines():
        uncommented = raw_line.strip()
        if not uncommented or uncommented.startswith("#"):
            continue
        if uncommented.endswith("\\"):
            pending += uncommented[:-1] + " "
            continue
        logical_lines.append(pending + uncommented)
        pending = ""
    if pending:
        logical_lines.append(pending)
    return tuple(tuple(shlex.split(line, comments=True)) for line in logical_lines)


def validate_pdf_eval_workflow(workflow_text: str) -> None:
    """Ratchet the exact unfiltered backend pytest step and its native support."""
    document = yaml.safe_load(workflow_text)
    assert isinstance(document, dict), "backend workflow must parse as a mapping"
    jobs = document.get("jobs")
    assert isinstance(jobs, dict), "backend workflow must contain jobs"
    backend = jobs.get("backend")
    assert isinstance(backend, dict), "backend workflow must contain the backend job"
    steps = backend.get("steps")
    assert isinstance(steps, list), "backend job steps must be a list"

    test_index, test_step = _step(steps, "Test (pytest + coverage)")
    assert test_step.get("working-directory") == "backend"
    run = test_step.get("run")
    assert isinstance(run, str)
    pytest_commands = [
        command
        for command in _executable_commands(run)
        if len(command) >= 3 and command[0] == "pytest" and command[1:3] == ("-n", "4")
    ]
    assert len(pytest_commands) == 1, "expected the exact unfiltered `pytest -n 4` command"
    pytest_command = pytest_commands[0]
    assert pytest_command == (
        "pytest",
        "-n",
        "4",
        "--cov=app",
        "--cov-report=term",
        "-q",
        "|",
        "tee",
        "pytest-output.txt",
    ), "backend pytest command must remain exact and unfiltered"
    env = test_step.get("env")
    assert isinstance(env, dict)
    assert env.get("NETOPS_REQUIRE_REPORT_PDF_EVAL") == "1", (
        "NETOPS_REQUIRE_REPORT_PDF_EVAL must be exactly the string '1' on the unfiltered "
        "backend pytest step"
    )

    native_index, native_step = _step(steps, "Install report PDF native dependencies")
    assert native_index < test_index, "report PDF native install must precede backend pytest"
    native_run = native_step.get("run")
    assert isinstance(native_run, str)
    install_commands = [
        command
        for command in _executable_commands(native_run)
        if "apt-get" in command and "install" in command
    ]
    assert len(install_commands) == 1, "expected one executable apt-get install command"
    install_tokens = set(install_commands[0])
    for package in REQUIRED_NATIVE_PACKAGES:
        assert package in install_tokens, f"missing token-exact native package {package}"
