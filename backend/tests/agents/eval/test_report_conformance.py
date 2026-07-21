"""Exact report-conformance and redaction bite proofs (P4 W4-T3, ADR-0053)."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import re
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml

from app.engines.reports import RedactionViolationError, render_artifacts
from app.engines.reports import render as report_render
from app.engines.reports.payloads import ReportPayload, ReportSection
from tests.agents.eval import report_conformance as conformance_helper
from tests.agents.eval.report_conformance import (
    AUTHORIZATION_FINDING,
    PEM_FINDING,
    REQUIRED_NATIVE_PACKAGES,
    CompletenessError,
    ReportConformanceCase,
    assert_pdf_extracted_text_semantics,
    assert_pdf_semantics,
    case_by_kind,
    is_pdf_native_runtime_unavailable,
    load_report_conformance_cases,
    parse_csv_bytes,
    plant_report_secrets,
    remove_required_observed_row,
    scan_artifact_bytes,
    validate_completeness,
    validate_pdf_eval_workflow,
)

pytestmark = pytest.mark.eval

_REPO_ROOT = Path(__file__).resolve().parents[4]
_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "backend-gates.yml"
_PYPROJECT = _REPO_ROOT / "backend" / "pyproject.toml"
_LOCK = _REPO_ROOT / "backend" / "requirements.lock.txt"
_KINDS = ("change", "compliance_posture", "access_review", "audit_integrity")


@pytest.fixture(params=_KINDS)
def report_case(request: pytest.FixtureRequest) -> ReportConformanceCase:
    return case_by_kind(str(request.param))


def _render_real_or_skip(payload: ReportPayload) -> list[Any]:
    """Keep native-runtime handling around the render call and nowhere else."""
    try:
        artifacts = render_artifacts(payload)
    except (ImportError, OSError) as exc:
        if not is_pdf_native_runtime_unavailable(exc):
            raise
        flag = os.environ.get("NETOPS_REQUIRE_REPORT_PDF_EVAL")
        if flag is None:
            pytest.skip(f"real report-PDF runtime unavailable locally: {exc}")
        pytest.fail(
            "NETOPS_REQUIRE_REPORT_PDF_EVAL is present, but the real WeasyPrint/Pango "
            f"runtime is unavailable: {exc}",
            pytrace=False,
        )
    return artifacts


def _artifact_map(artifacts: list[Any]) -> dict[str, Any]:
    return {artifact.format.value: artifact for artifact in artifacts}


def _workflow_document() -> dict[str, Any]:
    document = yaml.safe_load(_WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _named_step(document: dict[str, Any], name: str) -> dict[str, Any]:
    steps = document["jobs"]["backend"]["steps"]
    matches = [step for step in steps if step.get("name") == name]
    assert len(matches) == 1
    return matches[0]


def test_manifest_reconstructs_all_four_goldens_and_validates_anchors() -> None:
    cases = load_report_conformance_cases()

    assert tuple(case.kind for case in cases) == _KINDS
    for case in cases:
        assert case.payload.kind == case.kind
        assert case.golden_csv_rows
        validate_completeness(case, case.payload)


@pytest.mark.parametrize(
    ("kind", "anchor_name"),
    (
        ("change", "change-request-lifecycle"),
        ("change", "change-request-transition-sequences"),
        ("compliance_posture", "daily-posture-days-and-gaps"),
        ("access_review", "break-glass-event-keys"),
        ("audit_integrity", "daily-integrity-days-and-gaps"),
        ("audit_integrity", "generation-time-attestation-fields"),
        ("audit_integrity", "integrity-gap-finding"),
    ),
)
def test_manifest_loader_bites_when_a_declared_anchor_is_deleted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    anchor_name: str,
) -> None:
    manifest_path = (
        _REPO_ROOT
        / "backend"
        / "tests"
        / "agents"
        / "eval"
        / "fixtures"
        / "report_conformance_cases.json"
    )
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    case = next(item for item in document["cases"] if item["kind"] == kind)
    original_count = len(case["anchors"])
    case["anchors"] = [anchor for anchor in case["anchors"] if anchor["name"] != anchor_name]
    assert len(case["anchors"]) == original_count - 1, "manifest mutation anchor disappeared"

    mutated_manifest = tmp_path / "report_conformance_cases.json"
    mutated_manifest.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(conformance_helper, "_MANIFEST", mutated_manifest)

    with pytest.raises(ValueError, match="anchor names/order drifted"):
        load_report_conformance_cases()


def test_emitted_csv_exactly_matches_the_parsed_w3_golden(
    report_case: ReportConformanceCase, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(report_render, "_render_pdf", lambda _payload: b"%PDF-1.7 stub")

    artifacts = _artifact_map(render_artifacts(report_case.payload))
    csv_artifact = artifacts["csv"]

    assert parse_csv_bytes(csv_artifact.content) == report_case.golden_csv_rows
    assert scan_artifact_bytes(csv_artifact.content) == frozenset()


def test_each_completeness_anchor_bites_when_observed_evidence_is_removed(
    report_case: ReportConformanceCase,
) -> None:
    for anchor_index, anchor in enumerate(report_case.anchors):
        for row_index in range(len(anchor.required_rows)):
            mutated = remove_required_observed_row(report_case, anchor_index, row_index)
            with pytest.raises(CompletenessError, match=re.escape(anchor.name)):
                validate_completeness(report_case, mutated)


def test_audit_attestation_timestamp_must_equal_payload_generated_at() -> None:
    case = case_by_kind("audit_integrity")
    mutated = case.payload.model_copy(
        update={"generated_at": case.payload.generated_at + timedelta(minutes=1)}
    )

    with pytest.raises(CompletenessError, match="generated_at"):
        validate_completeness(case, mutated)


def test_pdf_semantic_comparator_bites_on_deleted_or_reordered_logical_units() -> None:
    payload = ReportPayload(
        kind="change",
        title="Synthetic Semantic Report",
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 2, tzinfo=UTC),
        generated_at=datetime(2026, 7, 2, 0, 5, tzinfo=UTC),
        regime_tags=("SOC 2", "PCI DSS"),
        sections=(
            ReportSection(
                title="Evidence table",
                columns=("Key", "Value"),
                rows=(
                    ("alpha", "first observation"),
                    ("beta", "second observation"),
                ),
            ),
        ),
        notes=("Closing audit note",),
    )
    extracted_text = """\
Synthetic Semantic Report
Regime ta
gs: SOC 2, PCI DSS
Report kind change
Period start (UTC) 2026-07-01T00:00:00+00:00
Period end (UTC) 2026-07-02T00:00:00+00:00
Generated at (UTC) 2026-07-02T00:05:00+00:00
Evidence table
Key Value
alpha first observation
Key Value
beta second observation
Closing audit note
"""

    assert_pdf_extracted_text_semantics(extracted_text, payload)

    mutations = (
        extracted_text.replace("Evidence table\n", "", 1),
        extracted_text.replace("beta second observation\n", "", 1),
        extracted_text.replace("Closing audit note\n", "", 1),
        extracted_text.replace(
            "alpha first observation\nKey Value\nbeta second observation",
            "beta second observation\nKey Value\nalpha first observation",
            1,
        ),
    )
    for mutated_text in mutations:
        assert mutated_text != extracted_text, "PDF-text mutation anchor disappeared"
        with pytest.raises(AssertionError, match="missing/out of order"):
            assert_pdf_extracted_text_semantics(mutated_text, payload)


def test_real_pdf_semantics_clean_scan_and_repeat_render_are_deterministic(
    report_case: ReportConformanceCase,
) -> None:
    first = _artifact_map(_render_real_or_skip(report_case.payload))
    second = _artifact_map(_render_real_or_skip(report_case.payload))

    assert set(first) == set(second) == {"csv", "pdf"}
    for artifact_format in ("csv", "pdf"):
        left = first[artifact_format]
        right = second[artifact_format]
        assert left.content == right.content
        assert left.sha256 == right.sha256
        assert left.size_bytes == right.size_bytes == len(left.content)
        assert hashlib.sha256(left.content).hexdigest() == left.sha256
        assert scan_artifact_bytes(left.content) == frozenset()

    assert_pdf_semantics(first["pdf"].content, report_case.payload)

    if report_case.kind == "audit_integrity":
        cells = [
            cell for section in report_case.payload.sections for row in section.rows for cell in row
        ]
        digests = [cell for cell in cells if re.fullmatch(r"[0-9a-f]{64}", cell)]
        assert digests, "the clean scanner's SHA-256 allowance must be non-vacuous"


@pytest.mark.parametrize(
    ("plant", "field_path", "rule"),
    [
        ("authorization", "sections[0].columns[0]", "deny_field_name:authorization"),
        ("pem", "sections[0].rows[0][1]", "value_pattern:pem_private_key"),
    ],
)
def test_enabled_redaction_rejects_each_exact_plant(plant: str, field_path: str, rule: str) -> None:
    payload = plant_report_secrets(case_by_kind("change").payload, plant)

    with pytest.raises(RedactionViolationError) as raised:
        render_artifacts(payload)

    assert raised.value.field_path == field_path
    assert raised.value.rule == rule


@pytest.mark.parametrize(
    ("plant", "expected_finding"),
    (("authorization", AUTHORIZATION_FINDING), ("pem", PEM_FINDING)),
)
def test_disabled_bound_filter_makes_each_plant_visible_in_both_real_formats(
    monkeypatch: pytest.MonkeyPatch,
    plant: str,
    expected_finding: str,
) -> None:
    payload = plant_report_secrets(case_by_kind("change").payload, plant)
    monkeypatch.setattr(report_render, "enforce_redaction", lambda _payload: None)

    artifacts = _artifact_map(_render_real_or_skip(payload))

    assert set(artifacts) == {"csv", "pdf"}
    for artifact in artifacts.values():
        assert scan_artifact_bytes(artifact.content) == frozenset({expected_finding})


def test_independent_scanner_accepts_bytes_only_and_imports_no_filter_oracles() -> None:
    signature = inspect.signature(scan_artifact_bytes)
    assert tuple(signature.parameters) == ("artifact",)
    with pytest.raises(TypeError):
        scan_artifact_bytes("not-bytes")  # type: ignore[arg-type]

    helper_path = Path(inspect.getsourcefile(scan_artifact_bytes) or "")
    helper_source = helper_path.read_text(encoding="utf-8")

    def forbidden_filter_imports(source: str) -> set[str]:
        tree = ast.parse(source)
        findings: set[str] = set()
        forbidden_modules = {
            "app.engines.reports.redaction",
            "app.engines.reports.render",
        }
        forbidden_package_names = {
            "DENY_FIELD_NAME_TOKENS",
            "_VALUE_PATTERNS",
            "enforce_redaction",
            "redaction",
            "render",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                findings.update(
                    alias.name for alias in node.names if alias.name in forbidden_modules
                )
            if isinstance(node, ast.ImportFrom):
                if node.module in forbidden_modules:
                    findings.add(str(node.module))
                if node.module == "app.engines.reports":
                    findings.update(
                        alias.name for alias in node.names if alias.name in forbidden_package_names
                    )
        return findings

    assert forbidden_filter_imports(helper_source) == set()
    for prohibited_import in (
        "import app.engines.reports.redaction",
        "import app.engines.reports.render as report_render",
        "from app.engines.reports.redaction import _VALUE_PATTERNS",
        "from app.engines.reports import redaction",
        "from app.engines.reports import enforce_redaction",
    ):
        assert forbidden_filter_imports(f"{helper_source}\n{prohibited_import}\n")


def test_pdf_runtime_classifier_does_not_turn_assertion_or_extraction_bugs_into_skips() -> None:
    missing_other = ModuleNotFoundError("No module named 'other'", name="other")

    assert not is_pdf_native_runtime_unavailable(AssertionError("semantic mismatch"))
    assert not is_pdf_native_runtime_unavailable(ValueError("malformed PDF"))
    assert not is_pdf_native_runtime_unavailable(missing_other)


def test_csv_formula_neutralization_covers_all_seven_leads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(report_render, "_render_pdf", lambda _payload: b"%PDF-1.7 stub")
    hostile_rows = (
        ("=edge-01", "\tformula-probe"),
        ("+edge-02", "\rformula-probe"),
        ("-edge-03", "\nformula-probe"),
        ("@edge-04", "safe-synthetic-cell"),
    )
    payload = ReportPayload(
        kind="change",
        title="Formula Lead Conformance",
        period_start=datetime(2026, 7, 1, tzinfo=UTC),
        period_end=datetime(2026, 7, 2, tzinfo=UTC),
        generated_at=datetime(2026, 7, 2, 0, 5, tzinfo=UTC),
        sections=(
            ReportSection(
                title="Hostile hostnames and synthetic cells",
                columns=("Hostname", "Synthetic cell"),
                rows=hostile_rows,
            ),
        ),
    )

    csv_artifact = _artifact_map(render_artifacts(payload))["csv"]
    parsed = parse_csv_bytes(csv_artifact.content)
    emitted = parsed[9:13]

    assert emitted == tuple(
        tuple(
            f"'{cell}" if cell.startswith(("=", "+", "-", "@", "\t", "\r", "\n")) else cell
            for cell in row
        )
        for row in hostile_rows
    )


def test_pypdf_is_dev_only_and_hash_locked() -> None:
    project = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]
    dev = project["optional-dependencies"]["dev"]
    runtime = project["dependencies"]
    lock_text = _LOCK.read_text(encoding="utf-8")

    assert "pypdf>=6.14,<7" in dev
    assert not any(dependency.startswith("pypdf") for dependency in runtime)
    assert re.search(r"(?m)^pypdf==6\.[0-9.]+ \\$", lock_text)


def test_backend_pdf_eval_workflow_contract_is_structurally_enforced() -> None:
    validate_pdf_eval_workflow(_WORKFLOW.read_text(encoding="utf-8"))


@pytest.mark.parametrize("package", REQUIRED_NATIVE_PACKAGES)
def test_workflow_contract_bites_when_each_native_package_is_removed(package: str) -> None:
    document = _workflow_document()
    native = _named_step(document, "Install report PDF native dependencies")
    original = str(native["run"])
    native["run"], replacements = re.subn(
        rf"(?<![A-Za-z0-9_.+-]){re.escape(package)}(?![A-Za-z0-9_.+-])",
        "removed-package",
        original,
        count=1,
    )
    assert replacements == 1, f"mutation anchor disappeared: {package}"

    with pytest.raises(AssertionError, match=re.escape(package)):
        validate_pdf_eval_workflow(yaml.safe_dump(document, sort_keys=False))


def test_workflow_contract_bites_when_required_flag_is_removed() -> None:
    document = _workflow_document()
    test_step = _named_step(document, "Test (pytest + coverage)")
    assert test_step["env"].pop("NETOPS_REQUIRE_REPORT_PDF_EVAL") == "1"

    with pytest.raises(AssertionError, match="NETOPS_REQUIRE_REPORT_PDF_EVAL"):
        validate_pdf_eval_workflow(yaml.safe_dump(document, sort_keys=False))


@pytest.mark.parametrize(
    "selector",
    (
        "-k not_report_conformance",
        "-knot_report_conformance",
        "-m not_eval",
        "-mnot_eval",
        "--ignore tests/agents/eval/test_report_conformance.py",
        "--ignore=tests/agents/eval/test_report_conformance.py",
        "--deselect tests/agents/eval/test_report_conformance.py::"
        "test_manifest_reconstructs_all_four_goldens_and_validates_anchors",
        "--deselect=tests/agents/eval/test_report_conformance.py::"
        "test_manifest_reconstructs_all_four_goldens_and_validates_anchors",
        "--pyargs tests.agents.eval.test_report_conformance",
        "tests/agents/eval/test_report_conformance.py",
    ),
)
def test_workflow_contract_bites_when_backend_pytest_is_filtered(selector: str) -> None:
    document = _workflow_document()
    test_step = _named_step(document, "Test (pytest + coverage)")
    original = str(test_step["run"])
    exact_command = "pytest -n 4 --cov=app --cov-report=term -q"
    test_step["run"], replacements = re.subn(
        re.escape(exact_command),
        f"{exact_command} {selector}",
        original,
        count=1,
    )
    assert replacements == 1, "workflow pytest mutation anchor disappeared"

    with pytest.raises(AssertionError, match="unfiltered"):
        validate_pdf_eval_workflow(yaml.safe_dump(document, sort_keys=False))


def test_workflow_contract_bites_when_native_install_moves_after_pytest() -> None:
    document = _workflow_document()
    steps = document["jobs"]["backend"]["steps"]
    native_index = next(
        index
        for index, step in enumerate(steps)
        if step.get("name") == "Install report PDF native dependencies"
    )
    test_index = next(
        index for index, step in enumerate(steps) if step.get("name") == "Test (pytest + coverage)"
    )
    native = steps.pop(native_index)
    if native_index < test_index:
        test_index -= 1
    steps.insert(test_index + 1, native)

    with pytest.raises(AssertionError, match="precede"):
        validate_pdf_eval_workflow(yaml.safe_dump(document, sort_keys=False))
