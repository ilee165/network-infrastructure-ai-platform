"""Declarative compliance engine (M4; ADR-0018).

Evaluates operator-authored YAML compliance policies against a device's raw
config and its normalized models, emitting structured, LLM-free findings
(``pass`` | ``violation`` | ``skipped``) with concrete evidence. Pure logic over
the policy schema + a :class:`DeviceContext`; persistence/audit and the A9
LLM-boundary redaction live in the caller, not here (REPO-STRUCTURE §3.2).
"""

from app.engines.config_mgmt.compliance.engine import (
    DeviceContext,
    Finding,
    FindingStatus,
    evaluate_policy,
)
from app.engines.config_mgmt.compliance.loader import (
    DEFAULT_PACK_RESOURCE,
    load_default_pack,
    load_policy_yaml,
)
from app.engines.config_mgmt.compliance.schema import (
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
    "DEFAULT_PACK_RESOURCE",
    "DeviceContext",
    "Finding",
    "FindingStatus",
    "ModelAssert",
    "ModelPredicate",
    "Policy",
    "PolicyScope",
    "RegexAbsentAssert",
    "RegexPresentAssert",
    "Rule",
    "Severity",
    "evaluate_policy",
    "load_default_pack",
    "load_policy_yaml",
]
