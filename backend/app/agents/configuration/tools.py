"""Configuration Agent typed tool wrappers (M4 task 9, read-only).

All tools are classified READ_ONLY: the Configuration Agent *explains* drift and
compliance — it never mutates device state. A STATE_CHANGING tool may never
appear on this agent; the contract is asserted by the tests and enforced by
:meth:`~app.agents.framework.base.BaseSpecialistAgent.validate_definition`.
State-changing config push lands behind the M5 ChangeRequest workflow, not here.

Secret boundary (A9 — ADR-0017 §3). A device configuration is secret-bearing
(enable secrets, SNMP communities, routing/AAA/IPsec keys). The drift diff and
the compliance findings are computed **server-side over the raw, unredacted
config text** by ``engines/config_mgmt`` (T6 drift, T7 compliance) — fidelity
over secrecy at the storage boundary, so a security-relevant change to a secret
line is still detected. These tools sit at the **LLM boundary**: every fragment
of config-derived text they emit (a diff hunk, a finding's matched line) is run
through :func:`~app.llm.redaction.redact_prompt` *before* it is placed into the
JSON the model consumes. The agent therefore narrates only redacted results, and
no secret value ever reaches a provider — even though the redacting model wrapper
(:class:`~app.llm.redaction.RedactingChatModel`) would also strip it as a second
line of defence.

Each tool takes the already-computed drift/compliance result as plain JSON-able
input and returns a JSON string the model (and the agent's narration flow) can
consume directly. The tools hold no DB session and do no transport I/O: the
audited, raw-content read happened in the engine; the tool only redacts and
shapes the result for explanation.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Annotated, Any

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool
from app.llm.redaction import redact_prompt

#: Severity ordering, worst-first, for resolving a device's overall posture
#: (ADR-0018 §3: "a device's posture is the worst present").
_SEVERITY_RANK = {"violation": 3, "warn": 2, "info": 1}


def _redact(text: str) -> str:
    """Redact a fragment of config-derived text at the LLM boundary (A9)."""
    return redact_prompt(text)


def _redact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a finding with its (secret-bearing) ``evidence`` redacted.

    Only the ``evidence`` field can carry matched config lines; the rule id,
    severity, and status are operator-authored metadata and are passed through.
    """
    redacted = dict(finding)
    evidence = redacted.get("evidence")
    if isinstance(evidence, str):
        redacted["evidence"] = _redact(evidence)
    return redacted


# ---------------------------------------------------------------------------
# explain_drift_diff — narrate a (redacted) drift diff
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def explain_drift_diff(
    device_id: Annotated[
        str,
        Field(description="UUID of the device whose drift is being explained."),
    ],
    has_drift: Annotated[
        bool,
        Field(description="Whether the server-side diff against the baseline was non-empty."),
    ],
    diff: Annotated[
        str,
        Field(
            description=(
                "The unified diff of the device's current config against its approved "
                "baseline, computed server-side over the raw config. May be empty when "
                "there is no drift."
            )
        ),
    ] = "",
) -> str:
    """Explain a configuration drift diff with secrets redacted (read-only).

    Takes the unified diff computed server-side (``engines/config_mgmt`` over the
    raw, unredacted config) and returns a JSON object with ``device_id``,
    ``has_drift``, the **redacted** ``diff`` text, and the redacted changed
    lines (``added`` / ``removed``). Every config-derived fragment passes through
    the A9 redaction layer first, so secret values (SNMP communities, enable
    secrets, keys) are replaced by stable ``<<REDACTED:...>>`` tokens before the
    text reaches the model — the model still sees *that* a secret line changed,
    never the secret itself (ADR-0017 §3). Read-only: no device or DB write.
    """
    redacted_diff = _redact(diff) if diff else ""
    added: list[str] = []
    removed: list[str] = []
    for line in redacted_diff.splitlines():
        # Skip unified-diff file headers (---/+++) so only content changes show.
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].lstrip())
        elif line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:].lstrip())
    return json.dumps(
        {
            "device_id": device_id,
            "has_drift": has_drift,
            "diff": redacted_diff,
            "added": added,
            "removed": removed,
        }
    )


# ---------------------------------------------------------------------------
# assess_device_vs_policy — narrate (redacted) per-rule compliance findings
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def assess_device_vs_policy(
    device_id: Annotated[
        str,
        Field(description="UUID of the device being assessed."),
    ],
    policy_id: Annotated[
        str,
        Field(description="Identifier of the compliance policy the device was evaluated against."),
    ],
    findings: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Per-rule compliance findings computed server-side over the raw config: "
                "each has rule_id, severity, status (pass/violation/skipped), and evidence."
            )
        ),
    ],
) -> str:
    """Assess a device against a policy, returning redacted per-rule findings.

    Takes the structured findings produced server-side by the compliance engine
    (ADR-0018, deterministic and LLM-free) and returns a JSON object with
    ``device_id``, ``policy_id``, and the findings with each finding's
    secret-bearing ``evidence`` line redacted through the A9 layer before it
    reaches the model. The rule id, severity, and status are operator-authored
    metadata and are preserved verbatim so the model can cite which rule failed
    and how severely. Read-only — explains an already-computed assessment.
    """
    return json.dumps(
        {
            "device_id": device_id,
            "policy_id": policy_id,
            "findings": [_redact_finding(f) for f in findings],
        }
    )


# ---------------------------------------------------------------------------
# summarize_compliance_posture — aggregate findings into a device posture
# ---------------------------------------------------------------------------


@netops_tool(classification=ToolClassification.READ_ONLY)
async def summarize_compliance_posture(
    device_id: Annotated[
        str,
        Field(description="UUID of the device whose compliance posture to summarize."),
    ],
    findings: Annotated[
        list[dict[str, Any]],
        Field(
            description=(
                "Per-rule compliance findings computed server-side: each has rule_id, "
                "severity, status (pass/violation/skipped), and evidence."
            )
        ),
    ],
) -> str:
    """Summarize a device's overall compliance posture (read-only, redacted).

    Aggregates the server-side findings into status counts and the device's
    overall ``posture`` — the worst severity among the rules in violation
    (ADR-0018 §3: a device's posture is the worst present), or ``"compliant"``
    when nothing is in violation. Returns the worst offending rules with their
    A9-redacted evidence so the model can name *what* failed without ever seeing
    a secret value. Read-only — no device or DB write.
    """
    counts: Counter[str] = Counter()
    worst_rank = 0
    worst_severity = "compliant"
    offenders: list[dict[str, Any]] = []
    for finding in findings:
        status = str(finding.get("status", "skipped"))
        counts[status] += 1
        if status == "violation":
            severity = str(finding.get("severity", "info"))
            rank = _SEVERITY_RANK.get(severity, 0)
            if rank > worst_rank:
                worst_rank = rank
                worst_severity = severity
            offenders.append(_redact_finding(finding))
    return json.dumps(
        {
            "device_id": device_id,
            "posture": worst_severity,
            "counts": dict(counts),
            "offenders": offenders,
        }
    )


# ---------------------------------------------------------------------------
# Public surface for the agent package
# ---------------------------------------------------------------------------

CONFIGURATION_TOOLS = [
    explain_drift_diff,
    assess_device_vs_policy,
    summarize_compliance_posture,
]

__all__ = [
    "CONFIGURATION_TOOLS",
    "assess_device_vs_policy",
    "explain_drift_diff",
    "summarize_compliance_posture",
]
