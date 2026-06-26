"""Deterministic firewall-policy + posture analysis (P2 W3-T1, ADR-0037 §2).

Three rule-hygiene analyses over an ordered list of
:class:`~app.schemas.normalized.NormalizedFirewallRule` —

* **shadowed** — an earlier *enabled* rule fully matches a later rule's traffic
  with a DIFFERENT action, so the later rule is unreachable (a misconfiguration);
* **redundant** — an earlier *enabled* rule fully matches a later rule with the
  SAME action, so the later rule adds nothing (often zero ``hit_count``);
* **overly_permissive** — an ``allow`` rule with ``any`` source/destination (and,
  more broadly, ``any`` service), an unbounded exposure;

plus **posture** checks across firewall rules and ACLs (missing logging on an
allow, a management-plane service exposed to any source, a permit-any ACL).

Determinism (ADR-0037 §2): every decision is a set/predicate over already-normalized
fields — never LLM judgment — so the findings are reproducible for the W5-T1
precision/recall corpus. The *list order* of the rules is the policy evaluation
order (a firewall evaluates top-down); ``position`` is carried only for reporting.

Coverage model (ADR-0034 §5 limitation, recorded not hidden): a rule's match set
is compared **dimension by dimension as string sets** — an empty tuple means *any*
(firewall convention) and covers everything; a specific set covers another iff it
is a superset of it. Address objects are compared by their literal name/CIDR
string; this engine does **not** do CIDR-subnet math or address-group expansion, so
it flags *exact-and-superset* shadow/redundancy, not semantic subnet containment.
That keeps the analysis deterministic and false-positive-free at the cost of not
catching subnet-level shadowing — a deliberate trade for a provable gate.

Secret hygiene: firewall/NAT/ACL records are config metadata and carry no secret
(ADR-0034 §2); this engine reads only their structural fields. The free-text
``description`` is surfaced as evidence but A9-redacted at the tool boundary
(:mod:`app.agents.security.tools`), never here.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.schemas.normalized import (
    AclAction,
    FirewallAction,
    NormalizedAclEntry,
    NormalizedFirewallRule,
)
from app.schemas.security import FindingCategory, FindingSeverity, SecurityFinding

__all__ = [
    "MANAGEMENT_SERVICES",
    "analyze_firewall_rules",
    "analyze_security_posture",
]

#: Service / application identities that expose the device management plane. A
#: match against an ``allow`` rule with an ``any`` source is a high-severity
#: posture finding (the management plane must never be reachable from anywhere).
#: Compared case-insensitively against a rule's ``services`` and ``applications``.
MANAGEMENT_SERVICES: frozenset[str] = frozenset(
    {"ssh", "telnet", "snmp", "netconf", "https-mgmt", "http-mgmt", "rdp", "winrm"}
)

#: Literal wildcard tokens a match dimension may carry instead of an empty tuple.
#: ADR-0034 §5 says "empty tuple means *any*", but the real Wave-2 plugins emit the
#: vendor token verbatim — PAN-OS ``<member>any</member>`` → ``("any",)``, FortiOS
#: ``srcaddr: [{"name": "all"}]`` → ``("all",)``. A dimension is therefore *any*
#: when it is empty OR contains one of these tokens (case-insensitive), so the
#: overly-permissive / shadow / management-exposure checks do not silently
#: under-report the most common real-world "any" rule.
_WILDCARD_TOKENS: frozenset[str] = frozenset({"any", "all"})


def _dim_is_any(dimension: tuple[str, ...]) -> bool:
    """True iff a single match dimension is *any* (empty or a wildcard token).

    A dimension matches everything when it is empty or contains a wildcard token
    (``any``/``all``) — a rule whose source is ``[any, host-1]`` still matches any
    source (firewall convention).
    """
    return not dimension or any(member.casefold() in _WILDCARD_TOKENS for member in dimension)


#: Severity ranking (worst-first) for stable, deterministic ordering of findings.
_SEVERITY_RANK: dict[FindingSeverity, int] = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


def _rule_evidence(rule: NormalizedFirewallRule) -> dict[str, Any]:
    """Project a firewall rule to its secret-free normalized evidence fields."""
    return {
        "name": rule.name,
        "position": rule.position,
        "enabled": rule.enabled,
        "action": rule.action.value,
        "source_zones": list(rule.source_zones),
        "destination_zones": list(rule.destination_zones),
        "source_addresses": list(rule.source_addresses),
        "destination_addresses": list(rule.destination_addresses),
        "applications": list(rule.applications),
        "services": list(rule.services),
        "logging": rule.logging,
        "hit_count": rule.hit_count,
        "description": rule.description,
    }


def _acl_evidence(entry: NormalizedAclEntry) -> dict[str, Any]:
    """Project an ACL entry to its secret-free normalized evidence fields."""
    return {
        "acl_name": entry.acl_name,
        "action": entry.action.value,
        "protocol": entry.protocol,
        "sequence": entry.sequence,
        "source": str(entry.source) if entry.source is not None else None,
        "destination": str(entry.destination) if entry.destination is not None else None,
        "source_port": entry.source_port,
        "destination_port": entry.destination_port,
        "hits": entry.hits,
    }


def _dim_covers(covering: tuple[str, ...], covered: tuple[str, ...]) -> bool:
    """True iff the *covering* match dimension is a superset of *covered*.

    Firewall convention: an empty tuple OR a wildcard token (``any``/``all``) means
    *any*. ``any`` covers everything; a specific set never covers ``any`` (the
    ``any`` rule matches strictly more); otherwise membership is a string-set
    superset test (ADR-0034 §5 — literal comparison, no CIDR math).
    """
    if _dim_is_any(covering):  # covering = any -> matches everything
        return True
    if _dim_is_any(covered):  # covered = any but covering is specific -> not covered
        return False
    return set(covering) >= set(covered)


def _covers(covering: NormalizedFirewallRule, covered: NormalizedFirewallRule) -> bool:
    """True iff *covering*'s match set is a superset of *covered*'s on every dim."""
    return (
        _dim_covers(covering.source_zones, covered.source_zones)
        and _dim_covers(covering.destination_zones, covered.destination_zones)
        and _dim_covers(covering.source_addresses, covered.source_addresses)
        and _dim_covers(covering.destination_addresses, covered.destination_addresses)
        and _dim_covers(covering.applications, covered.applications)
        and _dim_covers(covering.services, covered.services)
    )


def _is_any(*dimensions: tuple[str, ...]) -> bool:
    """True iff every given match dimension is *any* (empty or a wildcard token)."""
    return all(_dim_is_any(dim) for dim in dimensions)


def _shadow_or_redundant(
    rules: Sequence[NormalizedFirewallRule],
) -> list[SecurityFinding]:
    """Flag each enabled rule fully covered by an earlier enabled rule.

    Same action as the covering rule -> ``redundant``; different action ->
    ``shadowed`` (the later rule is unreachable). Only the FIRST covering
    predecessor is reported per rule, so a rule yields at most one such finding.
    """
    findings: list[SecurityFinding] = []
    for i, rule in enumerate(rules):
        if not rule.enabled:
            continue
        for earlier in rules[:i]:
            if not earlier.enabled or not _covers(earlier, rule):
                continue
            if earlier.action == rule.action:
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.REDUNDANT,
                        severity=FindingSeverity.LOW,
                        rule_name=rule.name,
                        rule_position=rule.position,
                        related_rule_name=earlier.name,
                        evidence=_rule_evidence(rule),
                        rationale=(
                            f"Rule '{rule.name}' is fully covered by earlier rule "
                            f"'{earlier.name}' with the same '{rule.action.value}' action, so it "
                            "never adds anything"
                            + (
                                f" (hit_count={rule.hit_count})"
                                if rule.hit_count is not None
                                else ""
                            )
                            + "."
                        ),
                        suggested_remediation=(
                            f"Remove redundant rule '{rule.name}'; earlier rule "
                            f"'{earlier.name}' already covers its traffic."
                        ),
                    )
                )
            else:
                # A deny intended to block traffic that an earlier allow already
                # permits is a security gap (the deny is dead) — HIGH; an allow
                # shadowed by an earlier deny is a functionality gap — MEDIUM.
                blocks_dead = rule.action != FirewallAction.ALLOW
                severity = FindingSeverity.HIGH if blocks_dead else FindingSeverity.MEDIUM
                findings.append(
                    SecurityFinding(
                        category=FindingCategory.SHADOWED,
                        severity=severity,
                        rule_name=rule.name,
                        rule_position=rule.position,
                        related_rule_name=earlier.name,
                        evidence=_rule_evidence(rule),
                        rationale=(
                            f"Rule '{rule.name}' ({rule.action.value}) is unreachable: earlier "
                            f"rule '{earlier.name}' ({earlier.action.value}) already matches all "
                            "of its traffic, so it never takes effect."
                        ),
                        suggested_remediation=(
                            f"Reorder or narrow rule '{earlier.name}' so '{rule.name}' can take "
                            f"effect, or remove '{rule.name}' if it is obsolete."
                        ),
                    )
                )
            break
    return findings


def _overly_permissive(
    rules: Sequence[NormalizedFirewallRule],
) -> list[SecurityFinding]:
    """Flag enabled ``allow`` rules with ``any`` source/destination (or service)."""
    findings: list[SecurityFinding] = []
    for rule in rules:
        if not rule.enabled or rule.action != FirewallAction.ALLOW:
            continue
        src_any = _is_any(rule.source_addresses)
        dst_any = _is_any(rule.destination_addresses)
        svc_any = _is_any(rule.services, rule.applications)
        if src_any and dst_any:
            findings.append(
                SecurityFinding(
                    category=FindingCategory.OVERLY_PERMISSIVE,
                    severity=FindingSeverity.HIGH,
                    rule_name=rule.name,
                    rule_position=rule.position,
                    evidence=_rule_evidence(rule),
                    rationale=(
                        f"Rule '{rule.name}' allows traffic from any source to any destination"
                        + (" on any service" if svc_any else "")
                        + " — an unbounded exposure."
                    ),
                    suggested_remediation=(
                        f"Constrain rule '{rule.name}' to the specific source and destination "
                        "(and service) it is meant to permit."
                    ),
                )
            )
        elif src_any or dst_any or svc_any:
            # Any single unconstrained dimension on an allow is broader than a
            # least-privilege rule (e.g. `corp -> db on ANY service`), matching the
            # module/schema contract ("any source, destination, OR service").
            unconstrained = [
                name
                for name, is_any in (
                    ("source", src_any),
                    ("destination", dst_any),
                    ("service", svc_any),
                )
                if is_any
            ]
            findings.append(
                SecurityFinding(
                    category=FindingCategory.OVERLY_PERMISSIVE,
                    severity=FindingSeverity.MEDIUM,
                    rule_name=rule.name,
                    rule_position=rule.position,
                    evidence=_rule_evidence(rule),
                    rationale=(
                        f"Rule '{rule.name}' leaves {', '.join(unconstrained)} unconstrained "
                        "(any) on an allow — broader than a least-privilege rule should be."
                    ),
                    suggested_remediation=(
                        f"Constrain rule '{rule.name}' to the specific source, destination, and "
                        "service it is meant to permit."
                    ),
                )
            )
    return findings


def _posture_firewall(
    rules: Sequence[NormalizedFirewallRule],
) -> list[SecurityFinding]:
    """Posture checks over firewall rules: missing logging, exposed mgmt plane."""
    findings: list[SecurityFinding] = []
    for rule in rules:
        if not rule.enabled or rule.action != FirewallAction.ALLOW:
            continue
        # Management-plane service reachable from any source.
        named_services = {s.casefold() for s in (*rule.services, *rule.applications)}
        exposed = sorted(named_services & MANAGEMENT_SERVICES)
        if exposed and _is_any(rule.source_addresses):
            findings.append(
                SecurityFinding(
                    category=FindingCategory.POSTURE,
                    severity=FindingSeverity.HIGH,
                    rule_name=rule.name,
                    rule_position=rule.position,
                    evidence=_rule_evidence(rule),
                    rationale=(
                        f"Rule '{rule.name}' permits management-plane service(s) "
                        f"{exposed} from any source — the management plane must not be "
                        "reachable from anywhere."
                    ),
                    suggested_remediation=(
                        f"Restrict rule '{rule.name}' to the management subnet(s) authorized to "
                        "reach the management plane."
                    ),
                )
            )
        # Permit rule without logging — no audit trail for allowed traffic.
        if rule.logging is False or rule.logging is None:
            findings.append(
                SecurityFinding(
                    category=FindingCategory.POSTURE,
                    severity=FindingSeverity.MEDIUM,
                    rule_name=rule.name,
                    rule_position=rule.position,
                    evidence=_rule_evidence(rule),
                    rationale=(
                        f"Allow rule '{rule.name}' has logging "
                        + ("disabled" if rule.logging is False else "unset")
                        + " — permitted traffic leaves no audit trail."
                    ),
                    suggested_remediation=(
                        f"Enable logging on allow rule '{rule.name}' so permitted sessions are "
                        "audited."
                    ),
                )
            )
    return findings


def _posture_acls(acls: Sequence[NormalizedAclEntry]) -> list[SecurityFinding]:
    """Advisory posture check over ACLs: a permit entry with unscoped endpoints.

    A ``None`` source/destination on a :class:`NormalizedAclEntry` is **ambiguous**:
    the normalized model (``IPv4Network | IPv6Network | None``) cannot represent a
    named address-group, so a vendor that uses object-groups collapses them to
    ``None`` exactly like a genuine ``any`` (e.g. cisco_nxos ``addrgroup`` →
    ``None``). The engine therefore cannot tell "permit any → any" from "permit
    group-A → group-B" from ``None`` alone. To avoid false-positive HIGH findings on
    scoped object-group rules, a permit ACE with both endpoints unscoped is flagged
    **LOW / advisory** ("verify"), with the ambiguity named in the rationale — not
    asserted as a definite over-broad violation. (A precise check needs a normalized
    wildcard/group distinction; deferred — recorded, not silent.)
    """
    findings: list[SecurityFinding] = []
    for entry in acls:
        if entry.action == AclAction.PERMIT and entry.source is None and entry.destination is None:
            findings.append(
                SecurityFinding(
                    category=FindingCategory.POSTURE,
                    severity=FindingSeverity.LOW,
                    rule_name=entry.acl_name,
                    rule_position=entry.sequence,
                    evidence=_acl_evidence(entry),
                    rationale=(
                        f"ACL '{entry.acl_name}' permits traffic with both source and destination "
                        "unscoped — either 'any → any' (over-broad) OR an unresolved address-group "
                        "the normalized model cannot represent. Verify the intended scope."
                    ),
                    suggested_remediation=(
                        f"Confirm ACL '{entry.acl_name}' is not 'any → any'; if it is, scope it to "
                        "the specific source and destination it must permit."
                    ),
                )
            )
    return findings


def _sort_key(finding: SecurityFinding) -> tuple[int, int, str, str]:
    """Stable order: severity (worst first), position, rule name, category."""
    return (
        _SEVERITY_RANK[finding.severity],
        finding.rule_position if finding.rule_position is not None else 1_000_000,
        finding.rule_name,
        finding.category.value,
    )


def analyze_firewall_rules(
    rules: Sequence[NormalizedFirewallRule],
) -> list[SecurityFinding]:
    """Analyze firewall rules for shadowed / redundant / overly-permissive issues.

    Deterministic and order-stable (sorted worst-severity-first). The input list
    order is the policy evaluation order. Returns one finding per detected issue;
    a clean policy returns an empty list.
    """
    findings = [*_shadow_or_redundant(rules), *_overly_permissive(rules)]
    return sorted(findings, key=_sort_key)


def analyze_security_posture(
    rules: Sequence[NormalizedFirewallRule],
    acls: Sequence[NormalizedAclEntry] = (),
) -> list[SecurityFinding]:
    """Assess security posture across firewall rules and ACLs (deterministic).

    Flags allow rules missing logging, management-plane services exposed to any
    source, and permit-any-to-any ACL entries. Order-stable (worst-first).
    """
    findings = [*_posture_firewall(rules), *_posture_acls(acls)]
    return sorted(findings, key=_sort_key)
