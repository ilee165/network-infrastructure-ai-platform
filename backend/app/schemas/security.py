"""Security Agent findings model (P2 W3-T1, ADR-0037 §3).

The deterministic firewall-policy analysis engine
(:mod:`app.engines.security.firewall`) emits :class:`SecurityFinding` rows; the
Security Agent (:mod:`app.agents.security`) *narrates* them — it never produces a
finding by free LLM judgment (ADR-0037 §2, the Configuration-agent "narrate"
pattern). Findings are **evidence-cited** (every finding references the offending
rule and carries its normalized fields as evidence, satisfying CLAUDE.md "Explain
all AI decisions") and **secret-free**: firewall / NAT policy and ACL entries are
config metadata (``NormalizedFirewallRule`` / ``NormalizedAclEntry`` are
secret-free by construction, ADR-0034 §2), and any free-text fragment surfaced to
the model is A9-redacted at the tool boundary regardless (ADR-0017 §3, defence in
depth — :mod:`app.agents.security.tools`).

The model is **frozen** and **rejects unknown fields** (``extra="forbid"``) — a
finding is evidence, not scratch space, mirroring
:class:`~app.schemas.normalized.NormalizedRecord`.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "FindingCategory",
    "FindingSeverity",
    "SecurityFinding",
]


class FindingSeverity(StrEnum):
    """Severity of a security finding (worst-first ordering by rank).

    Wire-stable strings: they appear in narrated findings and (W5-T1) the
    precision/recall corpus, so they are part of the deterministic contract.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(StrEnum):
    """The class of firewall/posture issue a finding flags (ADR-0037 §2/§3)."""

    #: A later rule whose traffic is fully matched by an earlier rule with a
    #: DIFFERENT action — the later rule is unreachable (a misconfiguration).
    SHADOWED = "shadowed"
    #: A later rule fully matched by an earlier rule with the SAME action — it
    #: adds nothing (often zero hit_count).
    REDUNDANT = "redundant"
    #: An ``allow`` rule with ``any`` source/destination (or service) — unbounded
    #: exposure.
    OVERLY_PERMISSIVE = "overly_permissive"
    #: A cross-config / ACL posture issue (missing logging on an allow, a
    #: management-plane service exposed to any source, a permit-any ACL).
    POSTURE = "posture"


class SecurityFinding(BaseModel):
    """One structured, evidence-cited, secret-free security finding (ADR-0037 §3).

    ``rule_name`` / ``rule_position`` reference the offending rule; for a
    ``shadowed`` / ``redundant`` finding ``related_rule_name`` names the earlier
    rule that covers it. ``evidence`` is the offending rule's normalized fields
    (secret-free; the tool redacts any free-text fragment at the LLM boundary).
    ``rationale`` explains WHY it is a finding and ``suggested_remediation`` is the
    deterministic, human-reviewable fix — proposed only as a four-eyes
    ChangeRequest draft, never auto-applied (ADR-0037 §1/§4).
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    category: FindingCategory
    severity: FindingSeverity
    #: Name of the offending rule (or ACL) the finding flags.
    rule_name: str = Field(min_length=1)
    #: Position of the offending rule in the policy, when known.
    rule_position: int | None = Field(default=None, ge=0)
    #: For shadowed/redundant findings, the earlier rule that covers this one.
    #: Optional, but non-empty when present (a blank reference is never useful).
    related_rule_name: str | None = Field(default=None, min_length=1)
    #: The offending rule's normalized fields (secret-free evidence, ADR-0034 §2).
    #: Required and non-empty — every finding is evidence-cited (ADR-0037 §3 /
    #: CLAUDE.md "explain all AI decisions"); a finding with no evidence is invalid.
    #: A plain dict: evidence is deterministic, write-once engine output that is
    #: never mutated after construction and is redacted on a *copy* of ``model_dump``
    #: at the tool boundary — so an immutability wrapper earns no real protection
    #: and only adds a dict-vs-proxy API footgun (PR #70 review).
    evidence: dict[str, Any] = Field(min_length=1)
    #: Why this is a finding (grounds CLAUDE.md "explain all AI decisions").
    rationale: str = Field(min_length=1)
    #: The deterministic, human-reviewable fix (drafted as a CR, never applied).
    suggested_remediation: str = Field(min_length=1)

    @model_validator(mode="after")
    def _require_correlation_for_shadow_redundant(self) -> SecurityFinding:
        """A shadowed/redundant finding must cite the covering rule (ADR-0037 §3).

        These categories are inherently relational — "rule X is covered by rule Y";
        a finding that omits ``related_rule_name`` carries no correlation context and
        is invalid, so the contract is enforced structurally, not by convention.
        """
        if (
            self.category in (FindingCategory.SHADOWED, FindingCategory.REDUNDANT)
            and not self.related_rule_name
        ):
            raise ValueError(
                f"a '{self.category.value}' finding must name the covering rule via "
                "related_rule_name"
            )
        return self
