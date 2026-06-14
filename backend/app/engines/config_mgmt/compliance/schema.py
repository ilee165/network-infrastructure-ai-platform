"""Declarative compliance policy schema (M4; ADR-0018).

A compliance policy is an operator-authored YAML document validated by these
Pydantic models. The schema fixes the *contract* shared by the engine
(:mod:`app.engines.config_mgmt.compliance.engine`) and the seeded policy pack
(:mod:`app.engines.config_mgmt.compliance.loader`):

* a :class:`PolicyScope` — which vendors / roles / sites a policy applies to
  (``"*"`` is a wildcard token; an empty/omitted list means "any");
* a closed, discriminated set of assertion types (ADR-0018 §2):
  :class:`RegexPresentAssert`, :class:`RegexAbsentAssert` over the **raw**
  config text, and :class:`ModelAssert` over a named **normalized** model with a
  closed predicate vocabulary. The set is closed *by design* — a genuinely new
  check requires an ADR amendment plus a new assertion model here, never an
  ad-hoc mini-language (ADR-0018 "Negative" / Alternatives §1).

The models carry no evaluation logic — that lives in the engine. They only
parse, validate, and reject malformed policy documents at load time, so a typo
in a policy fails loudly instead of silently passing a device.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "WILDCARD",
    "ModelAssert",
    "ModelPredicate",
    "Policy",
    "PolicyScope",
    "RegexAbsentAssert",
    "RegexPresentAssert",
    "Rule",
    "Severity",
]

#: Scope wildcard token: a ``"*"`` entry (or an empty list) matches any value.
WILDCARD = "*"


class Severity(StrEnum):
    """Finding severity (ADR-0018 §3): a device's posture is the worst present."""

    INFO = "info"
    WARN = "warn"
    VIOLATION = "violation"


class ModelPredicate(StrEnum):
    """Closed predicate vocabulary for :class:`ModelAssert` (ADR-0018 §2)."""

    NON_EMPTY = "non_empty"
    EQUALS = "equals"
    CONTAINS = "contains"
    COUNT_EQ = "count_eq"
    COUNT_GTE = "count_gte"
    COUNT_LTE = "count_lte"


class _StrictModel(BaseModel):
    """Reject unknown keys so a misspelled policy field fails at load, not silently."""

    model_config = ConfigDict(extra="forbid")


class PolicyScope(_StrictModel):
    """Which devices a policy applies to (ADR-0018 §4).

    A policy applies to a device iff its vendor, role, and site each match the
    corresponding list — where a list is satisfied by an exact membership, the
    :data:`WILDCARD` token, or being empty/omitted ("any"). Matching is
    case-insensitive on the dimension values.
    """

    vendors: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    sites: list[str] = Field(default_factory=list)


class _RegexAssertBase(_StrictModel):
    """Common shape of the two raw-text regex assertions.

    ``pattern`` is validated as a compilable Python regex at load time so a
    malformed expression is rejected with the policy, never at evaluation.
    Patterns are matched multiline against the raw snapshot text by the engine.
    """

    pattern: str

    @field_validator("pattern")
    @classmethod
    def _pattern_compiles(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:  # pragma: no cover - exercised via schema tests
            raise ValueError(f"invalid regex pattern: {exc}") from exc
        return value


class RegexPresentAssert(_RegexAssertBase):
    """Passes iff ``pattern`` matches somewhere in the raw config (ADR-0018 §2)."""

    type: Literal["regex_present"] = "regex_present"


class RegexAbsentAssert(_RegexAssertBase):
    """Passes iff ``pattern`` matches nowhere in the raw config (ADR-0018 §2)."""

    type: Literal["regex_absent"] = "regex_absent"


class ModelAssert(_StrictModel):
    """Predicate over a named normalized model (ADR-0018 §2).

    ``model`` names a normalized collection supplied to the engine (e.g.
    ``ntp_servers``, ``acl_entries``, ``interfaces``); ``predicate`` is one of
    the closed :class:`ModelPredicate` set. ``value`` is required for the
    value-taking predicates (``equals``/``contains`` and the ``count_*``
    family) and forbidden for ``non_empty`` — enforced here so a malformed rule
    cannot reach evaluation.
    """

    type: Literal["model_assert"] = "model_assert"
    model: str
    predicate: ModelPredicate
    value: int | str | None = None

    @field_validator("model")
    @classmethod
    def _model_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("model_assert.model must be a non-empty model name")
        return value

    @model_validator(mode="after")
    def _count_predicates_require_value(self) -> ModelAssert:
        """count_* predicates require a non-null integer value (ADR-0018 §2).

        Enforced here so a malformed rule is rejected at policy-load time rather
        than crashing with an unhandled exception inside the evaluation engine.
        """
        _count_predicates = {
            ModelPredicate.COUNT_EQ,
            ModelPredicate.COUNT_GTE,
            ModelPredicate.COUNT_LTE,
        }
        if self.predicate in _count_predicates and self.value is None:
            raise ValueError(f"{self.predicate} requires a non-null integer value, got None")
        return self


Assertion = Annotated[
    RegexPresentAssert | RegexAbsentAssert | ModelAssert,
    Field(discriminator="type"),
]


class Rule(_StrictModel):
    """One policy rule: an id, a severity, an optional description, an assertion."""

    id: str
    severity: Severity
    description: str | None = None
    assert_: Assertion = Field(alias="assert")

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @field_validator("id")
    @classmethod
    def _id_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("rule.id must be non-empty")
        return value


class Policy(_StrictModel):
    """One version of a declarative compliance policy (ADR-0018 §1)."""

    id: str
    version: int
    scope: PolicyScope = Field(default_factory=PolicyScope)
    rules: list[Rule]

    @field_validator("id")
    @classmethod
    def _id_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("policy.id must be non-empty")
        return value

    @field_validator("rules")
    @classmethod
    def _rules_unique_and_present(cls, value: list[Rule]) -> list[Rule]:
        if not value:
            raise ValueError("policy must declare at least one rule")
        seen: set[str] = set()
        for rule in value:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)
        return value
