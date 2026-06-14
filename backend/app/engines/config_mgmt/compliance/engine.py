"""Compliance evaluation engine (M4; ADR-0018).

Evaluates a :class:`~app.engines.config_mgmt.compliance.schema.Policy` against a
single device and emits structured :class:`Finding` rows. The engine is

* **deterministic and LLM-free** — every assertion is a regex match over raw
  text or a predicate over already-normalized data (ADR-0018 §2/§3). The
  Configuration Agent later *explains* these findings (after A9 redaction); it
  never *produces* them.
* **pure** — no DB access and no transport I/O. It consumes a
  :class:`DeviceContext` (the device's scope dimensions, its raw config text,
  and any normalized models already collected) and returns findings. Persisting
  / auditing the findings is the caller's job, mirroring the drift engine's
  separation of computation from persistence.

Scope resolution (ADR-0018 §4): a policy applies to a device iff the device's
vendor / role / site each satisfy the policy scope. A policy that does **not**
apply yields one ``skipped`` finding per rule — never ``pass`` — so "not in
scope" is never confused with "compliant". A ``model_assert`` referencing a
model the device has not collected likewise resolves to ``skipped`` (with a
reason), not a false ``pass`` (ADR-0018 "Negative").
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from uuid import UUID

import structlog

from app.engines.config_mgmt.compliance.schema import (
    WILDCARD,
    ModelAssert,
    ModelPredicate,
    Policy,
    PolicyScope,
    RegexAbsentAssert,
    RegexPresentAssert,
    Rule,
    Severity,
)

__all__ = [
    "DeviceContext",
    "Finding",
    "FindingStatus",
    "evaluate_policy",
]

logger = structlog.get_logger(__name__)

# Cap evidence lines so a pathological config (e.g. thousands of matching ACLs)
# cannot produce an unbounded finding payload.
_MAX_EVIDENCE_LINES = 20


class FindingStatus(StrEnum):
    """Outcome of evaluating one rule against one device (ADR-0018 §5)."""

    PASS = "pass"
    VIOLATION = "violation"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class DeviceContext:
    """The single device a policy is evaluated against.

    ``vendor`` / ``role`` / ``site`` drive scope resolution (any may be ``None``
    when unknown — an unknown dimension only matches a wildcard/empty scope
    list). ``raw_config`` is the verbatim snapshot text the ``regex_*``
    assertions match against. ``models`` maps a normalized-model name (as
    referenced by a ``model_assert.model``) to the collected rows for that model;
    a name absent from this mapping is treated as *uncollected* and yields a
    ``skipped`` finding, distinct from a present-but-empty model.
    """

    device_id: UUID
    vendor: str | None
    role: str | None
    site: str | None
    raw_config: str
    models: Mapping[str, Sequence[Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """One structured compliance finding (ADR-0018 §5).

    ``status`` is ``pass`` | ``violation`` | ``skipped``; ``severity`` is the
    rule's declared severity (carried even on ``pass``/``skipped`` so a caller
    can report posture per rule). ``evidence`` is the concrete justification: the
    matching line(s) for a regex violation, the offending/asserted rows for a
    model assertion, or the skip reason — never secret material is *added* here
    beyond what the matched config line already contains (the A9 redaction layer
    applies at the LLM boundary, ADR-0017 §3, not here).
    """

    device_id: UUID
    policy_id: str
    policy_version: int
    rule_id: str
    severity: Severity
    status: FindingStatus
    evidence: str


def _dimension_matches(value: str | None, allowed: list[str]) -> bool:
    """True iff *value* satisfies an *allowed* scope list (ADR-0018 §4).

    An empty list or one containing the :data:`WILDCARD` token matches any
    value (including ``None``). Otherwise *value* must be a case-insensitive
    member of the list; an unknown (``None``) value matches only the
    wildcard/empty case.
    """
    if not allowed or WILDCARD in allowed:
        return True
    if value is None:
        return False
    lowered = value.casefold()
    return any(lowered == candidate.casefold() for candidate in allowed)


def _device_in_scope(scope: PolicyScope, device: DeviceContext) -> bool:
    """True iff *device* falls within *scope* on every dimension (ADR-0018 §4)."""
    return (
        _dimension_matches(device.vendor, scope.vendors)
        and _dimension_matches(device.role, scope.roles)
        and _dimension_matches(device.site, scope.sites)
    )


def _eval_regex_present(assertion: RegexPresentAssert, raw_config: str) -> tuple[bool, str]:
    """A ``regex_present`` rule passes iff the pattern matches the raw config."""
    matches = [line for line in raw_config.splitlines() if re.search(assertion.pattern, line)]
    if matches:
        return True, _format_lines(matches)
    return False, f"pattern not found: {assertion.pattern!r}"


def _eval_regex_absent(assertion: RegexAbsentAssert, raw_config: str) -> tuple[bool, str]:
    """A ``regex_absent`` rule passes iff the pattern matches nowhere."""
    matches = [line for line in raw_config.splitlines() if re.search(assertion.pattern, line)]
    if matches:
        return False, _format_lines(matches)
    return True, f"pattern absent: {assertion.pattern!r}"


def _eval_model_assert(assertion: ModelAssert, device: DeviceContext) -> tuple[bool | None, str]:
    """Evaluate a ``model_assert`` predicate over a named normalized model.

    Returns ``(None, reason)`` when the referenced model was not collected for
    the device — the caller maps this to a ``skipped`` finding (never a false
    ``pass``, ADR-0018 "Negative"). Otherwise returns ``(passed, evidence)``.
    """
    if assertion.model not in device.models:
        return None, f"model not collected: {assertion.model!r}"

    rows = list(device.models[assertion.model])
    predicate = assertion.predicate

    if predicate is ModelPredicate.NON_EMPTY:
        passed = len(rows) > 0
        return passed, f"{assertion.model!r} has {len(rows)} row(s)"

    if predicate is ModelPredicate.EQUALS:
        passed = any(_row_equals(row, assertion.value) for row in rows)
        return passed, _format_rows(rows)

    if predicate is ModelPredicate.CONTAINS:
        passed = any(_row_contains(row, assertion.value) for row in rows)
        return passed, _format_rows(rows)

    # count_* family: compare row count against the integer ``value``.
    target = _as_int(assertion.value)
    count = len(rows)
    if predicate is ModelPredicate.COUNT_EQ:
        passed = count == target
    elif predicate is ModelPredicate.COUNT_GTE:
        passed = count >= target
    else:  # ModelPredicate.COUNT_LTE
        passed = count <= target
    return passed, f"{assertion.model!r} count={count} (target {predicate.value} {target})"


def _as_int(value: int | str | None) -> int:
    """Coerce a count predicate's ``value`` to ``int`` (schema guarantees set)."""
    if isinstance(value, bool):  # pragma: no cover - bools are not valid counts
        raise TypeError("count predicate value must be an integer, not bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    raise ValueError(f"count predicate requires an integer value, got {value!r}")


def _row_equals(row: Any, expected: Any) -> bool:
    """True iff *row* (or its string form) equals *expected*."""
    return row == expected or str(row) == str(expected)


def _row_contains(row: Any, needle: Any) -> bool:
    """True iff *needle* is contained in *row* (membership or substring)."""
    try:
        if needle in row:  # dict keys, list/tuple membership
            return True
    except TypeError:
        pass
    return str(needle) in str(row)


def _format_lines(lines: Sequence[str]) -> str:
    """Join matched config lines into bounded evidence text."""
    shown = list(lines)[:_MAX_EVIDENCE_LINES]
    suffix = (
        f"\n… (+{len(lines) - _MAX_EVIDENCE_LINES} more)"
        if len(lines) > _MAX_EVIDENCE_LINES
        else ""
    )
    return "\n".join(shown) + suffix


def _format_rows(rows: Sequence[Any]) -> str:
    """Render normalized rows into bounded evidence text."""
    shown = [str(row) for row in list(rows)[:_MAX_EVIDENCE_LINES]]
    suffix = (
        f"\n… (+{len(rows) - _MAX_EVIDENCE_LINES} more)" if len(rows) > _MAX_EVIDENCE_LINES else ""
    )
    return "\n".join(shown) + suffix


def _evaluate_rule(rule: Rule, device: DeviceContext) -> tuple[FindingStatus, str]:
    """Evaluate one in-scope rule, returning its status and evidence."""
    assertion = rule.assert_
    if isinstance(assertion, RegexPresentAssert):
        passed, evidence = _eval_regex_present(assertion, device.raw_config)
    elif isinstance(assertion, RegexAbsentAssert):
        passed, evidence = _eval_regex_absent(assertion, device.raw_config)
    else:  # ModelAssert
        model_passed, evidence = _eval_model_assert(assertion, device)
        if model_passed is None:
            return FindingStatus.SKIPPED, evidence
        passed = model_passed

    return (FindingStatus.PASS if passed else FindingStatus.VIOLATION), evidence


def evaluate_policy(policy: Policy, device: DeviceContext) -> list[Finding]:
    """Evaluate *policy* against *device*, returning one finding per rule.

    When *device* is out of *policy*'s scope, every rule yields a ``skipped``
    finding (ADR-0018 §4 — not ``pass``). Otherwise each rule is evaluated to
    ``pass`` / ``violation``, or ``skipped`` when a ``model_assert`` references
    an uncollected model. A fully compliant in-scope device reports every rule
    ``pass`` (the M4 exit criterion).
    """
    in_scope = _device_in_scope(policy.scope, device)
    findings: list[Finding] = []

    for rule in policy.rules:
        if not in_scope:
            status, evidence = FindingStatus.SKIPPED, "device out of policy scope"
        else:
            status, evidence = _evaluate_rule(rule, device)
        findings.append(
            Finding(
                device_id=device.device_id,
                policy_id=policy.id,
                policy_version=policy.version,
                rule_id=rule.id,
                severity=rule.severity,
                status=status,
                evidence=evidence,
            )
        )

    violations = sum(1 for f in findings if f.status is FindingStatus.VIOLATION)
    logger.info(
        "compliance.policy_evaluated",
        device_id=str(device.device_id),
        policy_id=policy.id,
        policy_version=policy.version,
        in_scope=in_scope,
        rules=len(policy.rules),
        violations=violations,
    )
    return findings
