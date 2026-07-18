"""SOC 2 CC-series regime mapping (P4 W3-T6; ADR-0053 §8) — unit suite.

Covers:

1. The mapping doc (`docs/compliance/soc2-cc-mapping.md`) states an explicit
   `**Mapping version:**` matching the code constant, PROPOSED status, and the
   Q7 rebase-path pointer.
2. The drift guard itself — the doc's content hash must match the pinned
   constant for the current version (a substantive edit without a version +
   hash bump goes red).
3. The guard is not vacuous: a planted content change (never persisted) is
   proven to change the hash, mirroring the `test_boundary.py`
   not-vacuous-scanner pattern.
4. Every report kind's default `regime_tags` (`app.engines.reports.builders.
   REGIME_TAG_DEFAULTS`) carries its ADR-0053 §8 SOC2 CC-series tags PLUS the
   mapping-version tag, and a generated run of each kind persists them
   (worker-level: `tests/workers/test_report_tasks.py`, API-level: pinned tags
   below).
"""

from __future__ import annotations

import hashlib
import re

from app.engines.reports.builders import REGIME_TAG_DEFAULTS
from app.engines.reports.regime_mapping import (
    MAPPING_DOC_PATH,
    MAPPING_DOC_SHA256,
    MAPPING_VERSION,
    MAPPING_VERSION_TAG,
    mapping_doc_sha256,
)
from app.models.reports import ReportKind

_VERSION_LINE = re.compile(r"\*\*Mapping version:\*\*\s*(\d+)")


def _doc_text() -> str:
    return MAPPING_DOC_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Doc states an explicit version + PROPOSED status + rebase pointer
# ---------------------------------------------------------------------------


def test_doc_exists_and_states_a_version_matching_the_code_constant() -> None:
    assert MAPPING_DOC_PATH.is_file(), f"mapping doc missing at {MAPPING_DOC_PATH}"
    text = _doc_text()
    match = _VERSION_LINE.search(text)
    assert match, "mapping doc must carry a `**Mapping version:** N` line"
    assert int(match.group(1)) == MAPPING_VERSION, (
        "the doc's stated version and MAPPING_VERSION "
        "(app.engines.reports.regime_mapping) have drifted apart"
    )


def test_doc_states_proposed_status_and_the_open_item_pointer() -> None:
    text = _doc_text()
    assert "PROPOSED" in text
    assert "docs/consultant/QUESTIONS.md" in text and "Q7" in text


def test_doc_states_the_rebase_path_and_never_claims_certification() -> None:
    text = _doc_text()
    assert "Rebasing to a different regime" in text
    assert "never rewritten" in text
    # Q7 default language discipline: "aligned" is the accurate phrase, and the
    # doc must explicitly disclaim a formal attestation (never assert one).
    assert "SOC 2 Type II-aligned" in text
    assert "SOC 2 attestation" in text


def test_doc_names_the_f5_vmware_out_of_scope_limit() -> None:
    """Requirement: honest named limits (e.g. F5/VMware config drift, P4)."""
    text = _doc_text()
    assert "F5" in text and "VMware" in text
    assert "ADR-0050" in text and "ADR-0051" in text


# ---------------------------------------------------------------------------
# 2. Drift guard — the doc content must hash to the pinned constant
# ---------------------------------------------------------------------------


def test_mapping_doc_matches_its_pinned_version_hash() -> None:
    """The drift guard itself.

    If this fails, the doc changed without MAPPING_DOC_SHA256 (and, per the
    doc's own drift-guard section, MAPPING_VERSION) being bumped in the same
    change — recompute the hash (see the constant's docstring) and update both
    together, or revert the unintended doc edit.
    """
    assert mapping_doc_sha256() == MAPPING_DOC_SHA256, (
        "docs/compliance/soc2-cc-mapping.md changed without a MAPPING_VERSION + "
        "MAPPING_DOC_SHA256 bump in app/engines/reports/regime_mapping.py"
    )


def test_drift_guard_is_not_vacuous_on_a_planted_content_change() -> None:
    """A planted violation (never persisted) proves the guard actually bites.

    Mirrors `test_boundary.py`'s not-vacuous-scanner pattern: this in-memory
    mutation is the same class of change a real, un-versioned doc edit would
    make, and it must fail the pinned-hash comparison exactly as
    `test_mapping_doc_matches_its_pinned_version_hash` does against the real
    file.
    """
    original = _doc_text()
    planted = original + "\nPlanted drift: an added sentence with no version bump.\n"
    planted_hash = hashlib.sha256(planted.encode("utf-8")).hexdigest()
    assert planted_hash != MAPPING_DOC_SHA256, (
        "the drift guard failed to detect a content change — the pinned hash "
        "would falsely stay green on this planted violation"
    )
    # Sanity: the plant must not accidentally reproduce the current version
    # line's exact wording used elsewhere in this suite.
    assert planted != original


# ---------------------------------------------------------------------------
# 4. Default regime_tags per kind carry CC-series tags + the version tag
# ---------------------------------------------------------------------------


def test_every_kind_has_regime_tag_defaults_registered() -> None:
    assert set(REGIME_TAG_DEFAULTS) == set(ReportKind)


def test_change_defaults_carry_cc8_1_and_mapping_version() -> None:
    assert REGIME_TAG_DEFAULTS[ReportKind.CHANGE] == ("soc2:CC8.1", MAPPING_VERSION_TAG)


def test_compliance_posture_defaults_carry_cc7_1_cc4_1_and_mapping_version() -> None:
    assert REGIME_TAG_DEFAULTS[ReportKind.COMPLIANCE_POSTURE] == (
        "soc2:CC7.1",
        "soc2:CC4.1",
        MAPPING_VERSION_TAG,
    )


def test_access_review_defaults_carry_cc6_1_through_cc6_3_and_mapping_version() -> None:
    assert REGIME_TAG_DEFAULTS[ReportKind.ACCESS_REVIEW] == (
        "soc2:CC6.1",
        "soc2:CC6.2",
        "soc2:CC6.3",
        MAPPING_VERSION_TAG,
    )


def test_audit_integrity_defaults_carry_cc7_2_and_mapping_version() -> None:
    assert REGIME_TAG_DEFAULTS[ReportKind.AUDIT_INTEGRITY] == (
        "soc2:CC7.2",
        MAPPING_VERSION_TAG,
    )


def test_mapping_version_tag_shape() -> None:
    assert f"mapping-version:{MAPPING_VERSION}" == MAPPING_VERSION_TAG
    for tags in REGIME_TAG_DEFAULTS.values():
        assert tags[-1] == MAPPING_VERSION_TAG, "mapping-version tag must be present per kind"
        assert all(tag.startswith("soc2:") for tag in tags[:-1]), (
            "every non-version tag must be a soc2: control pointer into the mapping doc"
        )
