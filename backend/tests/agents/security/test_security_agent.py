"""Security Agent core tests (P2 W3-T1, ADR-0037).

The Security Agent is a ``BaseSpecialistAgent`` whose tool registry contains ZERO
device-executing tools (ADR-0037 §1): two READ_ONLY analyses that NARRATE the
deterministic engine's findings, plus one STATE_CHANGING remediation tool whose
only effect is a gate-created ``security_remediation`` ChangeRequest draft. These
tests pin: identity/routing surface, the tool classification + read-only invariant,
the analysis tools over fixtures (W5-T1 seed), A9 redaction at the secret boundary,
and the remediation -> CR gate path (mirroring the DDI gate test, minus any device
write).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.agents.framework.approval import ChangeRequestGate
from app.agents.framework.tools import (
    AgentRunIdentity,
    ChangeRequestCreated,
    NetOpsTool,
    ToolClassification,
    agent_run_context,
    change_request_gate_context,
)
from app.agents.security import SecurityAgent, registry, security_agent
from app.agents.security.agent import SECURITY_NAME
from app.agents.security.tools import (
    SECURITY_TOOLS,
    _parse_acls,
    _parse_firewall_rules,
    analyze_firewall_policy,
    assess_security_posture,
    propose_firewall_remediation,
)
from app.core.security import Role
from app.llm.redaction import REDACTION_TOKENS
from app.models import (
    Base,
    ChangeRequest,
    ChangeRequestKind,
    ChangeRequestState,
    User,
)
from app.models import Role as RoleRow
from app.schemas.normalized import FirewallAction, NormalizedFirewallRule
from app.schemas.security import FindingCategory, FindingSeverity, SecurityFinding
from tests.agents.conftest import scripted_model

DEVICE = "11111111-1111-1111-1111-111111111111"
_DEVICE_UUID = uuid.UUID(DEVICE)

# A secret-bearing fragment an operator might paste into a rule description; the A9
# redaction layer recognizes the Cisco type-9 hash and must scrub it before any
# finding reaches the model.
_SECRET = "$9$nhEmQVczB7dqsO$X.NN.5KTHc.PmGwiL.S6/mQ.GW21Ek1dNXLm6F"


def _make_agent() -> SecurityAgent:
    return SecurityAgent()


def _rule_dump(
    name: str,
    *,
    action: FirewallAction = FirewallAction.ALLOW,
    enabled: bool = True,
    position: int | None = None,
    source_addresses: tuple[str, ...] = (),
    destination_addresses: tuple[str, ...] = (),
    services: tuple[str, ...] = (),
    logging: bool | None = True,
    hit_count: int | None = None,
    description: str | None = None,
) -> dict[str, Any]:
    """A JSON-able NormalizedFirewallRule dump, as the agent receives them."""
    return NormalizedFirewallRule(
        device_id=_DEVICE_UUID,
        collected_at=datetime.now(tz=UTC),
        source_vendor="panos",
        name=name,
        position=position,
        enabled=enabled,
        action=action,
        source_addresses=source_addresses,
        destination_addresses=destination_addresses,
        services=services,
        logging=logging,
        hit_count=hit_count,
        description=description,
    ).model_dump(mode="json")


# ---------------------------------------------------------------------------
# Identity / routing surface
# ---------------------------------------------------------------------------


class TestSecurityIdentity:
    def test_name_is_security(self) -> None:
        assert _make_agent().name == SECURITY_NAME == "security"

    def test_description_non_empty_and_on_topic(self) -> None:
        desc = _make_agent().description.lower()
        assert desc.strip()
        for token in ("firewall", "shadow", "overly-permissive", "posture", "audit"):
            assert token in desc

    def test_description_disambiguates_from_troubleshooting(self) -> None:
        # ADR-0037 §5: Security owns posture/audit over policy-as-data; live
        # single-flow reachability faults stay with Troubleshooting. The
        # description must steer that split so routing does not oscillate.
        desc = _make_agent().description.lower()
        assert "troubleshooting" in desc
        assert "read-only" in desc

    def test_system_prompt_non_empty(self) -> None:
        assert _make_agent().system_prompt.strip()

    def test_validate_definition_passes(self) -> None:
        _make_agent().validate_definition()

    def test_package_singleton_is_registered(self) -> None:
        assert security_agent.name == SECURITY_NAME
        assert SECURITY_NAME in registry


# ---------------------------------------------------------------------------
# Tool classification + read-only invariant (ADR-0037 §1)
# ---------------------------------------------------------------------------


class TestToolClassification:
    _READ_ONLY = {"analyze_firewall_policy", "assess_security_posture"}
    _STATE_CHANGING = {"propose_firewall_remediation"}

    def test_all_tools_are_netops_tool(self) -> None:
        for tool in _make_agent().tools:
            assert isinstance(tool, NetOpsTool)

    def test_read_only_tools_classified_read_only(self) -> None:
        by_name = {t.name: t for t in SECURITY_TOOLS}
        for name in self._READ_ONLY:
            assert by_name[name].classification is ToolClassification.READ_ONLY

    def test_remediation_tool_is_state_changing_with_security_kind(self) -> None:
        by_name = {t.name: t for t in SECURITY_TOOLS}
        for name in self._STATE_CHANGING:
            tool = by_name[name]
            assert tool.classification is ToolClassification.STATE_CHANGING
            assert tool.change_request_kind is ChangeRequestKind.SECURITY_REMEDIATION
            # A change-proposal tool requires engineer (like the DDI mutators).
            assert tool.min_role is Role.ENGINEER

    def test_no_device_executing_tool_registered(self) -> None:
        # The read-only invariant (ADR-0037 §1): no DIAGNOSTIC (device-executing)
        # tool, and the only mutation surface is a gate-routed CR draft — every
        # STATE_CHANGING tool carries a change_request_kind so the gate intercepts
        # it. There is NO tool that writes to a device inline.
        for tool in _make_agent().tools:
            assert tool.classification is not ToolClassification.DIAGNOSTIC
            if tool.classification is ToolClassification.STATE_CHANGING:
                assert tool.change_request_kind is ChangeRequestKind.SECURITY_REMEDIATION

    def test_tool_set_matches_declared_surface(self) -> None:
        names = {t.name for t in _make_agent().tools}
        assert names == self._READ_ONLY | self._STATE_CHANGING

    def test_build_graph_compiles(self) -> None:
        agent = _make_agent()
        graph = agent.build_graph(scripted_model([]))
        assert graph is not None


# ---------------------------------------------------------------------------
# Read-only analysis tools (deterministic findings — W5-T1 seed)
# ---------------------------------------------------------------------------


class TestAnalysisTools:
    async def test_analyze_firewall_policy_flags_overly_permissive(self) -> None:
        rules = [_rule_dump("permit-any", action=FirewallAction.ALLOW, position=1)]
        raw = await analyze_firewall_policy.ainvoke({"device_id": DEVICE, "rules": rules})
        payload = json.loads(raw)
        assert payload["device_id"] == DEVICE
        categories = {f["category"] for f in payload["findings"]}
        assert "overly_permissive" in categories

    async def test_analyze_firewall_policy_flags_shadowed_and_redundant(self) -> None:
        rules = [
            _rule_dump("deny-all", action=FirewallAction.DENY, position=1),
            _rule_dump(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=2,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("web",),
            ),
            _rule_dump("deny-all-2", action=FirewallAction.DENY, position=3),
        ]
        raw = await analyze_firewall_policy.ainvoke({"device_id": DEVICE, "rules": rules})
        payload = json.loads(raw)
        categories = {f["category"] for f in payload["findings"]}
        # allow-web is shadowed by deny-all; deny-all-2 is redundant with deny-all.
        assert "shadowed" in categories
        assert "redundant" in categories
        # Every finding cites the offending rule and carries a remediation.
        for finding in payload["findings"]:
            assert finding["rule_name"]
            assert finding["rationale"]
            assert finding["suggested_remediation"]

    async def test_analyze_firewall_policy_clean_policy_has_no_findings(self) -> None:
        rules = [
            _rule_dump(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("web",),
                services=("https",),
            ),
            _rule_dump("deny-rest", action=FirewallAction.DENY, position=2),
        ]
        raw = await analyze_firewall_policy.ainvoke({"device_id": DEVICE, "rules": rules})
        assert json.loads(raw)["findings"] == []

    async def test_assess_security_posture_flags_missing_logging(self) -> None:
        rules = [
            _rule_dump(
                "allow-web",
                action=FirewallAction.ALLOW,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("web",),
                services=("https",),
                logging=False,
            )
        ]
        raw = await assess_security_posture.ainvoke({"device_id": DEVICE, "rules": rules})
        payload = json.loads(raw)
        assert any(f["category"] == "posture" for f in payload["findings"])

    async def test_assess_security_posture_over_acls(self) -> None:
        acls = [
            {
                "device_id": DEVICE,
                "collected_at": datetime.now(tz=UTC).isoformat(),
                "source_vendor": "cisco_ios",
                "acl_name": "OUTSIDE_IN",
                "action": "permit",
                "protocol": "ip",
                "sequence": 10,
            }
        ]
        raw = await assess_security_posture.ainvoke({"device_id": DEVICE, "acls": acls})
        payload = json.loads(raw)
        assert any(f["rule_name"] == "OUTSIDE_IN" for f in payload["findings"])


# ---------------------------------------------------------------------------
# A9 redaction at the secret boundary
# ---------------------------------------------------------------------------


class TestFindingSchemaInvariants:
    """The SecurityFinding contract: evidence-cited + correlation-cited."""

    def test_shadowed_finding_requires_related_rule_name(self) -> None:
        with pytest.raises(ValidationError):
            SecurityFinding(
                category=FindingCategory.SHADOWED,
                severity=FindingSeverity.MEDIUM,
                rule_name="allow-web",
                evidence={"name": "allow-web"},
                rationale="unreachable",
                suggested_remediation="reorder",
            )

    def test_redundant_finding_requires_related_rule_name(self) -> None:
        with pytest.raises(ValidationError):
            SecurityFinding(
                category=FindingCategory.REDUNDANT,
                severity=FindingSeverity.LOW,
                rule_name="allow-dup",
                evidence={"name": "allow-dup"},
                rationale="adds nothing",
                suggested_remediation="remove",
            )

    def test_empty_evidence_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SecurityFinding(
                category=FindingCategory.OVERLY_PERMISSIVE,
                severity=FindingSeverity.HIGH,
                rule_name="permit-any",
                evidence={},  # evidence-cited contract: must be non-empty
                rationale="any to any",
                suggested_remediation="constrain",
            )

    def test_overly_permissive_finding_needs_no_related_rule(self) -> None:
        # Non-correlated categories are valid without related_rule_name.
        finding = SecurityFinding(
            category=FindingCategory.OVERLY_PERMISSIVE,
            severity=FindingSeverity.HIGH,
            rule_name="permit-any",
            evidence={"name": "permit-any"},
            rationale="any to any",
            suggested_remediation="constrain",
        )
        assert finding.related_rule_name is None

    def test_whitespace_only_related_rule_name_is_rejected(self) -> None:
        # A blank/whitespace correlation name is meaningless; a shadowed finding
        # must cite a real covering rule, not "   " (cubic PR #70).
        with pytest.raises(ValidationError):
            SecurityFinding(
                category=FindingCategory.SHADOWED,
                severity=FindingSeverity.MEDIUM,
                rule_name="allow-web",
                related_rule_name="   ",
                evidence={"name": "allow-web"},
                rationale="unreachable",
                suggested_remediation="reorder",
            )

    def test_evidence_is_immutable_after_construction(self) -> None:
        # evidence is "evidence, not scratch space" — frozen must mean the mapping
        # itself cannot be tampered with post-validation (cubic PR #70).
        finding = SecurityFinding(
            category=FindingCategory.OVERLY_PERMISSIVE,
            severity=FindingSeverity.HIGH,
            rule_name="permit-any",
            evidence={"name": "permit-any", "source_addresses": ["any"]},
            rationale="any to any",
            suggested_remediation="constrain",
        )
        with pytest.raises(TypeError):
            finding.evidence["name"] = "tampered"  # type: ignore[index]
        # And it still serializes to a plain JSON dict for the tool boundary.
        dumped = finding.model_dump(mode="json")
        assert dumped["evidence"] == {"name": "permit-any", "source_addresses": ["any"]}


class TestValidationErrorSanitization:
    """A malformed record cannot leak secret text via the validation exception."""

    def test_firewall_validation_error_drops_secret_bearing_input(self) -> None:
        # A malformed rule (invalid action) carrying a secret in its description.
        bad = {
            "device_id": DEVICE,
            "collected_at": datetime.now(tz=UTC).isoformat(),
            "source_vendor": "panos",
            "name": "r1",
            "enabled": True,
            "action": "definitely-not-a-valid-action",
            "description": f"temp {_SECRET}",
        }
        with pytest.raises(ValueError) as ei:  # noqa: PT011 - message asserted below
            _parse_firewall_rules([bad])
        message = str(ei.value)
        # The message names the error type/ordinal but NEVER the secret input — and
        # never the field NAME either (an extra-field loc is attacker-controllable).
        assert _SECRET not in message
        assert "firewall rule at index 0" in message
        assert "error 1" in message

    def test_acl_validation_error_is_sanitized(self) -> None:
        bad = {
            "device_id": DEVICE,
            "collected_at": datetime.now(tz=UTC).isoformat(),
            "source_vendor": "cisco_ios",
            "acl_name": "A1",
            "action": "not-permit-or-deny",
        }
        with pytest.raises(ValueError) as ei:  # noqa: PT011 - message asserted below
            _parse_acls([bad])
        assert "ACL entry at index 0" in str(ei.value)


class TestRedaction:
    async def test_secret_in_rule_description_is_redacted(self) -> None:
        # An operator pasted a secret into a rule description; the finding's
        # evidence must scrub it before the model sees it.
        rules = [
            _rule_dump(
                "permit-any",
                action=FirewallAction.ALLOW,
                position=1,
                description=f"temporary rule {_SECRET}",
            )
        ]
        raw = await analyze_firewall_policy.ainvoke({"device_id": DEVICE, "rules": rules})
        assert _SECRET not in raw, "secret in rule description leaked into analysis output"
        # The redaction sentinel is present, so the model still sees a secret existed.
        assert REDACTION_TOKENS["cisco_type89"] in raw


# ---------------------------------------------------------------------------
# Remediation -> ChangeRequest (gate path; never executes inline)
# ---------------------------------------------------------------------------


@pytest.fixture()
async def engine() -> AsyncIterator[AsyncEngine]:
    """In-memory async SQLite engine with the full schema + FK enforcement."""
    eng = create_async_engine("sqlite+aiosqlite://")

    @event.listens_for(eng.sync_engine, "connect")
    def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture()
def sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture()
def service(sessionmaker: async_sessionmaker[AsyncSession]):
    from app.services.change_requests import ChangeRequestService

    return ChangeRequestService(sessionmaker)


async def _seed_engineer(maker: async_sessionmaker[AsyncSession]) -> uuid.UUID:
    async with maker() as session:
        role = RoleRow(name=f"engineer-{uuid.uuid4().hex[:8]}")
        session.add(role)
        await session.flush()
        user = User(username=f"user-{uuid.uuid4().hex[:8]}", password_hash="x", role_id=role.id)
        session.add(user)
        await session.commit()
        return user.id


async def _all_crs(maker: async_sessionmaker[AsyncSession]) -> list[ChangeRequest]:
    async with maker() as session:
        return list((await session.execute(select(ChangeRequest))).scalars().all())


def _gate_factory(service: Any):
    def factory(identity: AgentRunIdentity) -> ChangeRequestGate:
        assert identity.user_id is not None
        return ChangeRequestGate(
            service,
            requester_id=identity.user_id,
            actor_role=identity.role,
            generating_session_id=identity.session_id,
            reasoning_trace_id=identity.reasoning_trace_id,
        )

    return factory


class TestRemediationCreatesChangeRequest:
    async def test_propose_remediation_creates_security_cr_and_does_not_execute(
        self,
        service: Any,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        engineer_id = await _seed_engineer(sessionmaker)
        with (
            agent_run_context(role=Role.ENGINEER, user_id=engineer_id),
            change_request_gate_context(_gate_factory(service)),
        ):
            result = await propose_firewall_remediation.ainvoke(
                {
                    "device_id": DEVICE,
                    "rule_name": "permit-any",
                    "remediation": "constrain source/destination; the rule permits any to any",
                    "change_summary": "tighten overly-permissive rule permit-any",
                }
            )
        # The path returned a draft CR, NOT the change's result (no apply happened).
        assert isinstance(result, ChangeRequestCreated)
        assert result.change_request_state == ChangeRequestState.DRAFT.value
        assert uuid.UUID(result.change_request_id)

        crs = await _all_crs(sessionmaker)
        assert len(crs) == 1
        cr = crs[0]
        assert cr.state is ChangeRequestState.DRAFT
        assert cr.kind is ChangeRequestKind.SECURITY_REMEDIATION
        assert cr.requester_id == engineer_id
        # The verbatim payload carries the proposed remediation arguments.
        assert cr.payload["rule_name"] == "permit-any"
        assert "constrain" in cr.payload["remediation"]
        # target_refs is id-only (device + rule) — never secret-bearing.
        assert cr.target_refs is not None
        assert cr.target_refs.get("device_id") == DEVICE
        assert cr.target_refs.get("rule") == "permit-any"

    async def test_remediation_requires_engineer_role(
        self,
        service: Any,
        sessionmaker: async_sessionmaker[AsyncSession],
    ) -> None:
        # A viewer cannot reach the change-proposal tool (RBAC, brief §7).
        from app.agents.framework.tools import RbacForbiddenError

        with (
            agent_run_context(role=Role.VIEWER),
            change_request_gate_context(_gate_factory(service)),
            pytest.raises(RbacForbiddenError),
        ):
            await propose_firewall_remediation.ainvoke(
                {
                    "device_id": DEVICE,
                    "rule_name": "permit-any",
                    "remediation": "disable the rule",
                }
            )
        # No CR was drafted by the denied call.
        assert await _all_crs(sessionmaker) == []
