"""Security Agent typed tool wrappers (P2 W3-T1, ADR-0037).

Two tiers, both crossing the agents -> engines/services boundary only through
``NetOpsTool`` wrappers (REPO-STRUCTURE §3.2 row 11, same sanctioned crossing the
packet-analysis agent uses toward ``app.engines``):

- **Read-only analyses** (``READ_ONLY``). ``analyze_firewall_policy`` (shadowed /
  redundant / overly-permissive rules) and ``assess_security_posture`` (missing
  logging, management-plane exposure, permit-any ACLs). Each takes already-collected
  normalized data (``NormalizedFirewallRule`` / ``NormalizedAclEntry`` dumps the
  discovery runner persisted) as plain JSON-able input, calls the **deterministic**
  analysis engine (:mod:`app.engines.security.firewall`), and returns a JSON object
  of :class:`~app.schemas.security.SecurityFinding` rows the model narrates. The
  engine DECIDES; the agent narrates (ADR-0037 §2) — no LLM judgment enters the
  analysis, so findings are reproducible for the W5-T1 corpus. These tools hold no
  DB session and do no transport I/O.

- **State-changing remediation** (``STATE_CHANGING``, ``change_request_kind =
  security_remediation``). ``propose_firewall_remediation`` does **not** write to a
  device. It carries no body of its own: the framework
  :class:`~app.agents.framework.approval.ChangeRequestGate` intercepts the call,
  CREATES a ``security_remediation`` ChangeRequest draft from the verbatim
  arguments, and the tool returns a
  :class:`~app.agents.framework.tools.ChangeRequestCreated` — four-eyes approval
  required, executed later only by the Automation Agent (ADR-0037 §1/§4). The
  Security Agent registers **no device-executing tool**; this gate-routed draft is
  its only write path (the read-only-invariant test guards it).

Secret boundary (A9 — ADR-0017 §3). Firewall/NAT/ACL records are config metadata
and carry no secret (ADR-0034 §2); even so, a rule's free-text ``description`` is
run through :func:`~app.llm.redaction.redact_prompt` before any finding reaches a
prompt, so an operator-pasted secret in a description becomes a stable
``<<REDACTED:...>>`` token — defence in depth, mirroring the DDI / Configuration
agents.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool
from app.engines.security.firewall import (
    analyze_firewall_rules,
    analyze_security_posture,
)
from app.llm.redaction import redact_prompt
from app.models.change_requests import ChangeRequestKind
from app.schemas.normalized import NormalizedAclEntry, NormalizedFirewallRule
from app.schemas.security import SecurityFinding

# ---------------------------------------------------------------------------
# Shared helpers (no transport I/O; redaction at the LLM boundary)
# ---------------------------------------------------------------------------


def _redact_finding(finding: SecurityFinding) -> dict[str, Any]:
    """Serialize a finding for the model, A9-redacting its free-text evidence.

    Only the offending rule's free-text ``description`` can carry an operator-set
    secret; every structural field (rule name, action, zones, addresses) is config
    metadata and passes through so the narration stays useful (ADR-0034 §2).
    """
    payload = finding.model_dump(mode="json")
    evidence = payload.get("evidence")
    if isinstance(evidence, dict):
        description = evidence.get("description")
        if isinstance(description, str):
            evidence["description"] = redact_prompt(description)
    return payload


def _parse_firewall_rules(rules: list[dict[str, Any]]) -> list[NormalizedFirewallRule]:
    """Validate already-collected normalized firewall-rule dumps into models."""
    return [NormalizedFirewallRule.model_validate(rule) for rule in rules]


def _parse_acls(acls: list[dict[str, Any]]) -> list[NormalizedAclEntry]:
    """Validate already-collected normalized ACL-entry dumps into models."""
    return [NormalizedAclEntry.model_validate(entry) for entry in acls]


# ---------------------------------------------------------------------------
# Read-only firewall-policy analysis
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def analyze_firewall_policy(
    device_id: Annotated[
        str,
        Field(description="UUID of the firewall whose collected policy to analyze."),
    ],
    rules: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Already-collected normalized firewall rules (NormalizedFirewallRule dumps) in "
                "policy evaluation order (top-down) — the persisted projection of the firewall "
                "policy read (ADR-0034)."
            )
        ),
    ],
) -> str:
    """Find shadowed, redundant, and overly-permissive firewall rules (read-only).

    Runs the deterministic analysis engine over the collected rules (in their
    top-down evaluation order) and returns a JSON object with ``device_id`` and a
    ``findings`` list — each carries a category (shadowed / redundant /
    overly_permissive), severity, the offending rule, the related (covering) rule
    where applicable, evidence, a rationale, and a suggested remediation. The
    analysis is rule-based (not LLM judgment), so it is reproducible. Every
    finding's free-text evidence is A9-redacted before it reaches the model.
    Read-only: no device or DB write.
    """
    parsed = _parse_firewall_rules(rules)
    findings = analyze_firewall_rules(parsed)
    return json.dumps({"device_id": device_id, "findings": [_redact_finding(f) for f in findings]})


@netops_tool(classification=ToolClassification.READ_ONLY)
async def assess_security_posture(
    device_id: Annotated[
        str,
        Field(description="UUID of the device whose security posture to assess."),
    ],
    rules: Annotated[
        list[dict[str, Any]],
        Field(
            default=[],
            description=(
                "Already-collected normalized firewall rules to assess for posture issues "
                "(missing logging, management-plane exposure)."
            ),
        ),
    ] = [],  # noqa: B006 - read-only default, never mutated
    acls: Annotated[
        list[dict[str, Any]],
        Field(
            default=[],
            description=(
                "Already-collected normalized ACL entries (NormalizedAclEntry dumps) to assess "
                "for over-broad permit-any rules."
            ),
        ),
    ] = [],  # noqa: B006 - read-only default, never mutated
) -> str:
    """Assess security posture across firewall rules and ACLs (read-only).

    Runs the deterministic posture checks over the collected firewall rules and
    ACLs and returns a JSON object with ``device_id`` and a ``findings`` list —
    permit rules without logging, management-plane services exposed to any source,
    and permit-any-to-any ACL entries, each with severity, evidence, rationale, and
    a suggested remediation. The analysis is rule-based and reproducible; free-text
    evidence is A9-redacted before it reaches the model. Read-only: no device or
    DB write.
    """
    parsed_rules = _parse_firewall_rules(rules)
    parsed_acls = _parse_acls(acls)
    findings = analyze_security_posture(parsed_rules, parsed_acls)
    return json.dumps({"device_id": device_id, "findings": [_redact_finding(f) for f in findings]})


# ---------------------------------------------------------------------------
# State-changing remediation — CREATES a ChangeRequest, never executes inline
# ---------------------------------------------------------------------------
#
# Carries no write body: the framework ChangeRequestGate intercepts the
# STATE_CHANGING call, authors a ``security_remediation`` ChangeRequest from the
# verbatim arguments, and the tool returns a ChangeRequestCreated. The body below
# is unreachable under any non-approved gate (the default), so it exists only to
# carry the schema + docstring the LLM routes on. ``target_refs`` projects the call
# arguments to the id-only refs recorded on the CR (never secret-bearing).


def _remediation_target_refs(args: dict[str, Any]) -> dict[str, Any] | None:
    refs: dict[str, Any] = {"device_id": args.get("device_id")}
    if args.get("rule_name"):
        refs["rule"] = args["rule_name"]
    return refs


@netops_tool(
    classification=ToolClassification.STATE_CHANGING,
    min_role="engineer",
    change_request_kind=ChangeRequestKind.SECURITY_REMEDIATION,
    target_refs=_remediation_target_refs,
)
async def propose_firewall_remediation(
    device_id: Annotated[str, Field(description="UUID of the target firewall/device.")],
    rule_name: Annotated[
        str, Field(description="Name of the offending firewall rule (or ACL) to remediate.")
    ],
    remediation: Annotated[
        str,
        Field(
            description=(
                "The proposed change in plain terms (e.g. 'disable shadowed rule', 'constrain "
                "source to the management subnet', 'enable logging') — recorded verbatim on the "
                "change request for a human to review."
            )
        ),
    ],
    change_summary: Annotated[
        str | None,
        Field(default=None, description="Optional one-line summary for the change request."),
    ] = None,
) -> str:
    """Propose a firewall remediation — creates a change request, does not apply it.

    State-changing: this never writes to the device. The framework gate creates a
    ``security_remediation`` ChangeRequest draft from these arguments and returns
    it for human (four-eyes) approval; the Automation Agent applies the change only
    after the CR is approved (ADR-0037 §4). Use this when, having found a policy
    issue, the user asks you to remediate it — you draft the change for approval,
    you do not make it.
    """
    raise AssertionError(  # pragma: no cover - gate intercepts before the body runs
        "propose_firewall_remediation must not execute inline; the ChangeRequest gate handles it"
    )


# ---------------------------------------------------------------------------
# Public surface for the agent package
# ---------------------------------------------------------------------------

SECURITY_READ_TOOLS = [
    analyze_firewall_policy,
    assess_security_posture,
]

SECURITY_WRITE_TOOLS = [
    propose_firewall_remediation,
]

SECURITY_TOOLS = [*SECURITY_READ_TOOLS, *SECURITY_WRITE_TOOLS]

__all__ = [
    "SECURITY_READ_TOOLS",
    "SECURITY_TOOLS",
    "SECURITY_WRITE_TOOLS",
    "analyze_firewall_policy",
    "assess_security_posture",
    "propose_firewall_remediation",
]
