"""Security analysis engine (P2 W3-T1, ADR-0037 §2).

Deterministic, LLM-free firewall-policy and posture analysis over already-collected
normalized data (``NormalizedFirewallRule`` + ``NormalizedAclEntry``). The engine
DECIDES (rule-based); the Security Agent only NARRATES the findings it returns
(ADR-0037 §2, the Configuration-agent "narrate" pattern) — so the findings are
reproducible for the W5-T1 precision/recall corpus.

Pure: no DB access, no transport I/O. It consumes normalized records and returns
:class:`~app.schemas.security.SecurityFinding` rows; persisting/auditing them is
the caller's job, mirroring the compliance engine's separation of computation from
persistence.
"""

from __future__ import annotations

from app.engines.security.firewall import (
    MANAGEMENT_SERVICES,
    analyze_firewall_rules,
    analyze_security_posture,
)

__all__ = [
    "MANAGEMENT_SERVICES",
    "analyze_firewall_rules",
    "analyze_security_posture",
]
