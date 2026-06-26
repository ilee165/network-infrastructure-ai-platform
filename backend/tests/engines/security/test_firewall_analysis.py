"""Deterministic firewall-policy + posture analysis engine tests (P2 W3-T1).

The engine (:mod:`app.engines.security.firewall`) is the rule-based core ADR-0037
§2 mandates: it DECIDES the findings, the Security Agent only narrates them. These
tests pin the deterministic detections (shadowed / redundant / overly-permissive /
posture) over fixtures with known issues — the same fixtures seed the W5-T1
precision/recall corpus — and the order-stability the corpus relies on.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from app.engines.security.firewall import (
    analyze_firewall_rules,
    analyze_security_posture,
)
from app.schemas.normalized import (
    AclAction,
    FirewallAction,
    NormalizedAclEntry,
    NormalizedFirewallRule,
)
from app.schemas.security import FindingCategory, FindingSeverity

_DEVICE = UUID("11111111-1111-1111-1111-111111111111")


def _rule(
    name: str,
    *,
    action: FirewallAction = FirewallAction.ALLOW,
    enabled: bool = True,
    position: int | None = None,
    source_zones: tuple[str, ...] = (),
    destination_zones: tuple[str, ...] = (),
    source_addresses: tuple[str, ...] = (),
    destination_addresses: tuple[str, ...] = (),
    applications: tuple[str, ...] = (),
    services: tuple[str, ...] = (),
    logging: bool | None = True,
    hit_count: int | None = None,
    description: str | None = None,
) -> NormalizedFirewallRule:
    return NormalizedFirewallRule(
        device_id=_DEVICE,
        collected_at=datetime.now(tz=UTC),
        source_vendor="panos",
        name=name,
        position=position,
        enabled=enabled,
        action=action,
        source_zones=source_zones,
        destination_zones=destination_zones,
        source_addresses=source_addresses,
        destination_addresses=destination_addresses,
        applications=applications,
        services=services,
        logging=logging,
        hit_count=hit_count,
        description=description,
    )


def _acl(
    name: str,
    *,
    action: AclAction = AclAction.PERMIT,
    sequence: int | None = None,
    source: str | None = None,
    destination: str | None = None,
) -> NormalizedAclEntry:
    return NormalizedAclEntry(
        device_id=_DEVICE,
        collected_at=datetime.now(tz=UTC),
        source_vendor="cisco_ios",
        acl_name=name,
        action=action,
        sequence=sequence,
        source=source,
        destination=destination,
    )


# ---------------------------------------------------------------------------
# Shadowed
# ---------------------------------------------------------------------------


class TestShadowed:
    def test_deny_any_shadows_later_allow(self) -> None:
        # A broad deny precedes a specific allow with the same (covered) traffic:
        # the allow can never take effect — flagged shadowed.
        rules = [
            _rule("deny-all", action=FirewallAction.DENY, position=1),  # any -> any
            _rule(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=2,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("10.0.1.5",),
            ),
        ]
        findings = analyze_firewall_rules(rules)
        shadowed = [f for f in findings if f.category is FindingCategory.SHADOWED]
        assert len(shadowed) == 1
        assert shadowed[0].rule_name == "allow-web"
        assert shadowed[0].related_rule_name == "deny-all"
        # An allow shadowed by a deny is a functionality gap -> MEDIUM.
        assert shadowed[0].severity is FindingSeverity.MEDIUM

    def test_allow_any_shadows_later_deny_is_high(self) -> None:
        # A broad allow precedes a specific deny: the deny is DEAD (traffic it
        # meant to block is already permitted) — a security gap, HIGH.
        rules = [
            _rule("allow-all", action=FirewallAction.ALLOW, position=1),  # any -> any
            _rule(
                "deny-bad",
                action=FirewallAction.DENY,
                position=2,
                source_addresses=("203.0.113.0/24",),
            ),
        ]
        findings = analyze_firewall_rules(rules)
        shadowed = [f for f in findings if f.category is FindingCategory.SHADOWED]
        assert len(shadowed) == 1
        assert shadowed[0].rule_name == "deny-bad"
        assert shadowed[0].severity is FindingSeverity.HIGH

    def test_specific_rule_does_not_shadow_an_any_rule(self) -> None:
        # A specific earlier rule cannot cover a later "any" rule (the any rule
        # matches strictly more), so no shadow is reported.
        rules = [
            _rule(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("10.0.0.5",),
            ),
            _rule("deny-all", action=FirewallAction.DENY, position=2),  # any -> any
        ]
        findings = analyze_firewall_rules(rules)
        assert [f for f in findings if f.category is FindingCategory.SHADOWED] == []


# ---------------------------------------------------------------------------
# Redundant
# ---------------------------------------------------------------------------


class TestRedundant:
    def test_same_action_superset_is_redundant(self) -> None:
        rules = [
            _rule(
                "allow-subnet",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("10.0.0.0/24", "10.0.1.0/24"),
                destination_addresses=("web",),
            ),
            _rule(
                "allow-host",
                action=FirewallAction.ALLOW,
                position=2,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("web",),
                hit_count=0,
            ),
        ]
        findings = analyze_firewall_rules(rules)
        redundant = [f for f in findings if f.category is FindingCategory.REDUNDANT]
        assert len(redundant) == 1
        assert redundant[0].rule_name == "allow-host"
        assert redundant[0].related_rule_name == "allow-subnet"
        assert redundant[0].severity is FindingSeverity.LOW

    def test_disabled_rules_are_not_analyzed(self) -> None:
        # A disabled earlier rule cannot shadow; a disabled later rule is not flagged.
        rules = [
            _rule("deny-all", action=FirewallAction.DENY, position=1, enabled=False),
            _rule(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=2,
                source_addresses=("10.0.0.5",),
                destination_addresses=("web",),
            ),
            _rule(
                "allow-web-dup",
                action=FirewallAction.ALLOW,
                position=3,
                enabled=False,
                source_addresses=("10.0.0.5",),
                destination_addresses=("web",),
            ),
        ]
        findings = analyze_firewall_rules(rules)
        # No shadow (disabled deny) and no redundant (disabled dup) finding.
        assert [f for f in findings if f.category is FindingCategory.SHADOWED] == []
        assert [f for f in findings if f.category is FindingCategory.REDUNDANT] == []


# ---------------------------------------------------------------------------
# Overly permissive
# ---------------------------------------------------------------------------


class TestOverlyPermissive:
    def test_allow_any_to_any_is_high(self) -> None:
        rules = [_rule("permit-any", action=FirewallAction.ALLOW, position=1)]
        findings = analyze_firewall_rules(rules)
        op = [f for f in findings if f.category is FindingCategory.OVERLY_PERMISSIVE]
        assert len(op) == 1
        assert op[0].severity is FindingSeverity.HIGH
        assert op[0].rule_name == "permit-any"

    def test_allow_any_source_any_service_is_medium(self) -> None:
        rules = [
            _rule(
                "permit-inbound",
                action=FirewallAction.ALLOW,
                position=1,
                destination_addresses=("dmz-web",),  # dst is specific, src is any
            )
        ]
        findings = analyze_firewall_rules(rules)
        op = [f for f in findings if f.category is FindingCategory.OVERLY_PERMISSIVE]
        assert len(op) == 1
        assert op[0].severity is FindingSeverity.MEDIUM

    def test_allow_any_service_only_is_medium(self) -> None:
        # Specific source AND destination but ANY service (`corp -> db on any`) is a
        # real least-privilege gap the narrow detector used to miss.
        rules = [
            _rule(
                "corp-to-db",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("corp",),
                destination_addresses=("db",),  # services empty -> any
            )
        ]
        op = [
            f
            for f in analyze_firewall_rules(rules)
            if f.category is FindingCategory.OVERLY_PERMISSIVE
        ]
        assert len(op) == 1
        assert op[0].severity is FindingSeverity.MEDIUM
        assert "service" in op[0].rationale

    def test_allow_any_destination_only_is_medium(self) -> None:
        rules = [
            _rule(
                "corp-egress",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("corp",),  # dst any, service specific
                services=("https",),
            )
        ]
        op = [
            f
            for f in analyze_firewall_rules(rules)
            if f.category is FindingCategory.OVERLY_PERMISSIVE
        ]
        assert len(op) == 1
        assert op[0].severity is FindingSeverity.MEDIUM
        assert "destination" in op[0].rationale

    def test_deny_any_to_any_is_not_overly_permissive(self) -> None:
        # A broad DENY is good hygiene (a default-deny), not an exposure.
        rules = [_rule("deny-any", action=FirewallAction.DENY, position=1)]
        op = [
            f
            for f in analyze_firewall_rules(rules)
            if f.category is FindingCategory.OVERLY_PERMISSIVE
        ]
        assert op == []

    def test_scoped_allow_is_clean(self) -> None:
        rules = [
            _rule(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("web",),
                services=("https",),
            )
        ]
        assert analyze_firewall_rules(rules) == []


# ---------------------------------------------------------------------------
# Posture
# ---------------------------------------------------------------------------


class TestPosture:
    def test_allow_without_logging_is_flagged(self) -> None:
        rules = [
            _rule(
                "allow-web",
                action=FirewallAction.ALLOW,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("web",),
                services=("https",),
                logging=False,
            )
        ]
        findings = analyze_security_posture(rules)
        logging_findings = [f for f in findings if "logging" in f.rationale]
        assert len(logging_findings) == 1
        assert logging_findings[0].severity is FindingSeverity.MEDIUM
        assert logging_findings[0].category is FindingCategory.POSTURE

    def test_management_plane_exposed_to_any_is_high(self) -> None:
        rules = [
            _rule(
                "mgmt-ssh",
                action=FirewallAction.ALLOW,
                destination_addresses=("core-1",),  # src is any
                services=("SSH",),  # case-insensitive match
                logging=True,
            )
        ]
        findings = analyze_security_posture(rules)
        mgmt = [f for f in findings if "management-plane" in f.rationale]
        assert len(mgmt) == 1
        assert mgmt[0].severity is FindingSeverity.HIGH

    def test_management_plane_from_specific_source_is_not_flagged(self) -> None:
        rules = [
            _rule(
                "mgmt-ssh",
                action=FirewallAction.ALLOW,
                source_addresses=("10.255.0.0/24",),  # specific mgmt subnet
                destination_addresses=("core-1",),
                services=("ssh",),
                logging=True,
            )
        ]
        findings = analyze_security_posture(rules)
        assert [f for f in findings if "management-plane" in f.rationale] == []

    def test_permit_any_any_acl_is_high(self) -> None:
        acls = [_acl("OUTSIDE_IN", action=AclAction.PERMIT, sequence=10)]  # any -> any
        findings = analyze_security_posture((), acls)
        assert len(findings) == 1
        assert findings[0].severity is FindingSeverity.HIGH
        assert findings[0].rule_name == "OUTSIDE_IN"

    def test_scoped_acl_permit_is_clean(self) -> None:
        acls = [_acl("OK", action=AclAction.PERMIT, source="10.0.0.0/24")]
        assert analyze_security_posture((), acls) == []


# ---------------------------------------------------------------------------
# Literal wildcard tokens (the real Wave-2 plugin encoding — ADR-0034 §5)
# ---------------------------------------------------------------------------


class TestLiteralWildcardTokens:
    """`any` (PAN-OS) / `all` (FortiOS) tokens are wildcards, not specific names.

    The plugins emit the vendor token verbatim (`source=("any",)` /
    `srcaddr=("all",)`), not an empty tuple, so the engine must treat them as
    *any* or it silently under-reports the most common real-world exposure.
    """

    def test_literal_any_to_all_is_overly_permissive_high(self) -> None:
        rules = [
            _rule(
                "permit-any",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("any",),  # PAN-OS encoding
                destination_addresses=("all",),  # FortiOS encoding
                services=("any",),
            )
        ]
        op = [
            f
            for f in analyze_firewall_rules(rules)
            if f.category is FindingCategory.OVERLY_PERMISSIVE
        ]
        assert len(op) == 1
        assert op[0].severity is FindingSeverity.HIGH

    def test_literal_any_shadows_later_rule(self) -> None:
        rules = [
            _rule(
                "deny-all",
                action=FirewallAction.DENY,
                position=1,
                source_addresses=("any",),
                destination_addresses=("any",),
            ),
            _rule(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=2,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("web",),
            ),
        ]
        shadowed = [
            f for f in analyze_firewall_rules(rules) if f.category is FindingCategory.SHADOWED
        ]
        assert len(shadowed) == 1
        assert shadowed[0].rule_name == "allow-web"
        assert shadowed[0].related_rule_name == "deny-all"

    def test_literal_any_source_exposes_management_plane(self) -> None:
        rules = [
            _rule(
                "mgmt-ssh",
                action=FirewallAction.ALLOW,
                source_addresses=("All",),  # case-insensitive wildcard
                destination_addresses=("core-1",),
                services=("ssh",),
                logging=True,
            )
        ]
        findings = analyze_security_posture(rules)
        assert any("management-plane" in f.rationale for f in findings)


# ---------------------------------------------------------------------------
# Determinism / ordering
# ---------------------------------------------------------------------------


class TestDeterminismAndOrdering:
    def test_clean_policy_returns_no_findings(self) -> None:
        rules = [
            _rule(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("10.0.0.0/24",),
                destination_addresses=("web",),
                services=("https",),
            ),
            _rule("deny-rest", action=FirewallAction.DENY, position=2),
        ]
        assert analyze_firewall_rules(rules) == []
        assert analyze_security_posture(rules) == []

    def test_findings_sorted_worst_severity_first(self) -> None:
        rules = [
            _rule("allow-all", action=FirewallAction.ALLOW, position=1),  # HIGH overly-permissive
            _rule(
                "allow-all-dup",
                action=FirewallAction.ALLOW,
                position=2,
            ),  # LOW redundant (covered by allow-all)
        ]
        findings = analyze_firewall_rules(rules)
        severities = [f.severity for f in findings]
        # Sorted worst-first: HIGH before LOW.
        assert severities == sorted(
            severities,
            key=lambda s: [
                FindingSeverity.CRITICAL,
                FindingSeverity.HIGH,
                FindingSeverity.MEDIUM,
                FindingSeverity.LOW,
                FindingSeverity.INFO,
            ].index(s),
        )
        assert findings[0].severity is FindingSeverity.HIGH

    def test_repeated_runs_are_identical(self) -> None:
        rules = [
            _rule("allow-all", action=FirewallAction.ALLOW, position=1),
            _rule("deny-bad", action=FirewallAction.DENY, position=2, source_addresses=("bad",)),
        ]
        first = analyze_firewall_rules(rules)
        second = analyze_firewall_rules(rules)
        assert first == second
