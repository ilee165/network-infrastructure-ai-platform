"""Automation Agent typed tool wrappers (M5 task #9, read-only).

The Automation Agent's *write* path is the deterministic, server-gated executor
(:meth:`~app.agents.automation.agent.AutomationAgent.execute`) — never a
model-invocable tool. A STATE_CHANGING tool here would be a write path the LLM
could trigger, exactly the risk the ChangeRequest spine eliminates (M5-PLAN risk
#4: a "change X" request must route to *draft-a-CR*, never to direct execution).
So every tool the agent exposes to the supervisor is classified READ_ONLY: the
model may only ask the agent to *narrate* the status/intent of an approved change,
not to apply one. The contract is asserted by the tests and enforced by
:meth:`~app.agents.framework.base.BaseSpecialistAgent.validate_definition`.

Secret boundary (A9 — ADR-0017 §3 / ADR-0020 §4). A config CR ``payload`` carries
a raw config fragment and a DDI CR ``payload`` carries DNS/record fields — both
secret-bearing. Any such content surfaced to the LLM passes
:func:`~app.llm.redaction.redact_prompt` first, so secret values become stable
``<<REDACTED:...>>`` tokens before the text reaches a model prompt — the redacting
model wrapper would also strip it as defence in depth.
"""

from __future__ import annotations

import json
from typing import Annotated

from pydantic import Field

from app.agents.framework.tools import ToolClassification, netops_tool
from app.llm.redaction import redact_prompt


@netops_tool(classification=ToolClassification.READ_ONLY)
async def summarize_change_request(
    change_request_id: Annotated[
        str,
        Field(description="Id of the ChangeRequest being summarized for the user."),
    ],
    kind: Annotated[
        str,
        Field(description="The CR kind ('config' or 'ddi_record')."),
    ],
    summary: Annotated[
        str,
        Field(
            description="Operator/agent-authored, secret-free one-line description of the change."
        ),
    ],
    content: Annotated[
        str,
        Field(
            description=(
                "The change content the approver reviewed (a config fragment or DDI "
                "record body). Secret-bearing — redacted here before it reaches the model."
            )
        ),
    ] = "",
) -> str:
    """Narrate an approved change request's intent with secrets redacted (read-only).

    Returns a JSON object with the CR id, kind, and the **A9-redacted** ``summary``
    and ``content`` so the model can explain *what* the change does
    (which lines/fields it touches) without ever seeing a secret value (enable
    secrets, SNMP communities, keys). Read-only: this tool applies nothing — the
    deterministic executor performs the gated write.
    """
    return json.dumps(
        {
            "change_request_id": change_request_id,
            "kind": kind,
            "summary": redact_prompt(summary),
            "content": redact_prompt(content) if content else "",
        }
    )


AUTOMATION_TOOLS = [summarize_change_request]

__all__ = ["AUTOMATION_TOOLS", "summarize_change_request"]
