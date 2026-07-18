"""Redaction choke-point unit set (P4 W3-T1; ADR-0053 §6 layer 2).

Deny-class field names (incl. section column headers), format-anchored value
patterns (PEM/JWT/AKIA/vendor prefixes), clean payloads passing, SHA-256 hex
digests NOT flagged (the ADR-0038 no-entropy-detection lesson), and the
fail-closed leak contract: the violation carries the FIELD PATH and rule only —
never the value.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from app.engines.reports.payloads import ReportPayload, ReportSection
from app.engines.reports.redaction import (
    DENY_FIELD_NAME_TOKENS,
    RedactionViolationError,
    enforce_redaction,
)

_START = datetime(2026, 7, 1, tzinfo=UTC)
_END = datetime(2026, 7, 8, tzinfo=UTC)
_GEN = datetime(2026, 7, 8, 5, 0, tzinfo=UTC)


def _payload(
    *,
    sections: tuple[ReportSection, ...] = (),
    notes: tuple[str, ...] = (),
    title: str = "Change Report",
) -> ReportPayload:
    return ReportPayload(
        kind="change",
        title=title,
        period_start=_START,
        period_end=_END,
        generated_at=_GEN,
        regime_tags=("soc2:CC8.1",),
        sections=sections,
        notes=notes,
    )


def _section(
    *rows: tuple[str, ...], columns: tuple[str, ...] = ("Field", "Value")
) -> ReportSection:
    return ReportSection(title="Data", columns=columns, rows=rows)


# ---------------------------------------------------------------------------
# Clean payloads pass
# ---------------------------------------------------------------------------


def test_clean_payload_passes() -> None:
    payload = _payload(
        sections=(_section(("Device", "core-sw-01"), ("State", "approved")),),
        notes=("Weekly change roll-up.",),
    )
    enforce_redaction(payload)  # must not raise


def test_sha256_hex_digests_are_not_flagged() -> None:
    """Evidence artifacts legitimately carry SHA-256 digests (ADR-0038 lesson).

    The audit-integrity report presents entry hashes; bare entropy detection
    would false-positive on the platform's own integrity evidence — the filter
    is format-anchored instead, so a 64-hex digest must pass.
    """
    digest = hashlib.sha256(b"artifact-bytes").hexdigest()
    payload = _payload(
        sections=(
            _section(
                ("Artifact digest", digest),
                ("Entry hash", hashlib.sha256(b"entry").hexdigest().upper()),
                columns=("Field", "Digest"),
            ),
        )
    )
    enforce_redaction(payload)  # must not raise


# ---------------------------------------------------------------------------
# Field-name deny class (incl. section column headers)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("token", DENY_FIELD_NAME_TOKENS)
def test_deny_class_column_header_rejects(token: str) -> None:
    payload = _payload(sections=(_section(columns=("Device", token.upper())),))
    with pytest.raises(RedactionViolationError) as excinfo:
        enforce_redaction(payload)
    assert excinfo.value.rule == f"deny_field_name:{token}"


def test_deny_class_is_case_insensitive_substring() -> None:
    payload = _payload(sections=(_section(columns=("Device", "SNMP Community String")),))
    with pytest.raises(RedactionViolationError) as excinfo:
        enforce_redaction(payload)
    assert "community" in excinfo.value.rule


# ---------------------------------------------------------------------------
# Format-anchored value patterns
# ---------------------------------------------------------------------------

# Secret-shaped fixtures are assembled at runtime via explicit concatenation so
# repo secret scanners (GitHub push protection, gitleaks) never see a literal
# token-shaped string in the blob; the redaction engine still receives the full
# assembled value.
_PEM = (
    "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA " + "PRIVATE KEY-----"
)
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    + "TJVA95OrM7E2cBab30RM"
)
_AKIA = "AKIA" + "IOSFODNN7EXAMPLE"
_ASIA = "ASIA" + "ABCDEFGHIJKLMNOP"
_GHP = "ghp_" + "AbCdEfGhIjKlMnOpQrStUvWx12345678"
_SLACK = "xoxb-" + "123456789012-abcdefghijklmn"
_ANTHROPIC = "sk-ant-" + "api03-abcdefghijklmnop"


@pytest.mark.parametrize(
    ("value", "rule"),
    [
        (_PEM, "value_pattern:pem_private_key"),
        (_JWT, "value_pattern:jwt"),
        (_AKIA, "value_pattern:aws_access_key_id"),
        (_ASIA, "value_pattern:aws_access_key_id"),
        (_GHP, "value_pattern:github_token"),
        (_SLACK, "value_pattern:slack_token"),
        (_ANTHROPIC, "value_pattern:anthropic_api_key"),
    ],
)
def test_secret_formatted_values_reject(value: str, rule: str) -> None:
    payload = _payload(sections=(_section(("Config excerpt", value)),))
    with pytest.raises(RedactionViolationError) as excinfo:
        enforce_redaction(payload)
    assert excinfo.value.rule == rule


def test_value_patterns_apply_to_notes_and_title() -> None:
    with pytest.raises(RedactionViolationError):
        enforce_redaction(_payload(notes=(f"appendix: {_PEM}",)))
    with pytest.raises(RedactionViolationError):
        enforce_redaction(_payload(title=f"Report {_AKIA}"))


def test_pem_certificate_block_is_not_flagged() -> None:
    """Certificates are public material; only PRIVATE KEY blocks reject."""
    cert = "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"
    enforce_redaction(_payload(sections=(_section(("TLS cert", cert)),)))


# ---------------------------------------------------------------------------
# Fail-closed leak contract: field path + rule only, NEVER the value
# ---------------------------------------------------------------------------


def test_violation_names_field_path_never_the_value() -> None:
    payload = _payload(sections=(_section(("Config excerpt", _PEM)),))
    with pytest.raises(RedactionViolationError) as excinfo:
        enforce_redaction(payload)
    err = excinfo.value
    # The path locates the cell precisely...
    assert err.field_path == "sections[0].rows[0][1]"
    # ...and NOTHING about the exception carries the secret value.
    assert "PRIVATE KEY" not in str(err)
    assert _PEM not in str(err)
    assert _PEM not in repr(err)
    assert not hasattr(err, "value")
