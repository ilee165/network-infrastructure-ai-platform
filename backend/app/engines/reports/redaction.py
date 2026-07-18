"""Render-time redaction filter — layer 2 of the ADR-0053 §6 contract.

THE choke point: every payload passes :func:`enforce_redaction` inside the
single payload→artifact path (:func:`app.engines.reports.render.render_artifacts`)
before any renderer sees it. It rejects on:

* **field-name deny-class** (case-insensitive substring over field names, mapping
  keys, and section column headers) — the pinned list below is the single
  source (ADR-0053 §6: the list lives in this one module);
* **format-anchored value patterns** — PEM private-key blocks, JWTs
  (``eyJ`` three-segment), AWS access-key ids (``AKIA``/``ASIA``), known vendor
  token prefixes.

**Deliberately NOT bare high-entropy detection** (ADR-0053 §6 / alternative 5):
evidence artifacts legitimately carry SHA-256 hex digests (artifact hashes, the
ADR-0038 ``entry_hash`` presentation) — an entropy detector would false-positive
on the audit-integrity report itself and be tuned into uselessness.

**Fail closed, leak nothing:** a hit raises :class:`RedactionViolationError`
carrying the FIELD PATH and the matched rule name ONLY — never the value. The
caller (the worker task) marks the run ``failed`` with the typed
``redaction_violation`` error class, increments
``netops_report_failures_total``, writes an audit entry, and persists no
partial artifact.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Final

from app.engines.reports.payloads import ReportPayload

__all__ = [
    "DENY_FIELD_NAME_TOKENS",
    "RedactionViolationError",
    "enforce_redaction",
]

#: The pinned field-name deny-class (ADR-0053 §6, case-insensitive substring).
#: Curated HERE and only here; W4-T3's planted-secret eval bites on removals.
DENY_FIELD_NAME_TOKENS: Final[tuple[str, ...]] = (
    "password",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "private_key",
    "credential",
    "authorization",
    "cookie",
    "community",  # SNMP
)

#: Format-anchored value patterns (name → compiled regex). Anchored to known
#: secret FORMATS — never bare entropy (see module docstring).
_VALUE_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("pem_private_key", re.compile(r"-----BEGIN[A-Z0-9 ]*PRIVATE KEY-----")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
)


class RedactionViolationError(Exception):
    """A payload failed the render-time redaction filter (fail-closed).

    Carries the offending FIELD PATH and rule name only — the value is never
    captured, so the failure record cannot itself leak the secret into logs,
    metrics, or the API (ADR-0053 §6).
    """

    def __init__(self, field_path: str, rule: str) -> None:
        self.field_path = field_path
        self.rule = rule
        super().__init__(f"redaction violation at {field_path!r} (rule: {rule})")


def _check_name(name: str, path: str) -> None:
    lowered = name.casefold()
    for token in DENY_FIELD_NAME_TOKENS:
        if token in lowered:
            raise RedactionViolationError(path, f"deny_field_name:{token}")


def _check_value(value: str, path: str) -> None:
    for rule_name, pattern in _VALUE_PATTERNS:
        if pattern.search(value):
            raise RedactionViolationError(path, f"value_pattern:{rule_name}")


def _walk(node: Any, path: str, *, names: bool) -> None:
    """Recursively scan *node*: keys/headers as names, strings as values.

    ``names=True`` marks a context whose STRING LEAVES are identifiers (section
    column headers), which are name-checked in addition to the value patterns.
    """
    if isinstance(node, str):
        if names:
            _check_name(node, path)
        _check_value(node, path)
        return
    if isinstance(node, Mapping):
        for key, child in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            if isinstance(key, str):
                _check_name(key, child_path)
            # Section column headers are identifiers, not free values: a builder
            # must not smuggle a "Password" column past the field-name class.
            child_names = names or key == "columns"
            _walk(child, child_path, names=child_names)
        return
    if isinstance(node, list | tuple | set | frozenset):
        for index, child in enumerate(node):
            _walk(child, f"{path}[{index}]", names=names)
        return
    # Numbers / booleans / None / datetimes-as-strings were already serialized
    # by model_dump(mode="json"); anything else has no string surface to scan.


def enforce_redaction(payload: ReportPayload) -> None:
    """Reject *payload* if any deny-class name or secret-format value appears.

    Raises:
        RedactionViolationError: naming the field path and rule ONLY (never the
            value). The single render path calls this before any renderer runs,
            so a hit means NO artifact is produced (fail closed).
    """
    dumped = payload.model_dump(mode="json")
    _walk(dumped, "", names=False)
