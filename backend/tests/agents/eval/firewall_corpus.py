"""Labelled firewall-policy-analysis corpus (P2 W5-T1, ADR-0037 / ADR-0033 §3).

Ground-truth fixtures for the precision/recall scorer in
:mod:`tests.agents.eval.test_firewall_analysis_eval`. Each :class:`LabelledCase` is a
small policy (an ordered list of :class:`NormalizedFirewallRule`, plus optional
:class:`NormalizedAclEntry` rows) carrying **ground-truth labels** — the
:class:`ExpectedFinding` rows the W3 deterministic service
(:mod:`app.engines.security.firewall`) **must** produce, keyed by
``(category, rule_name)``. Cases that should produce *no* finding (clean
negatives) carry an empty ``expected`` set, so a "flag-everything" service fails
precision (Requirement 3 / Exit criterion 1).

Why a held-out corpus, not the engine's own unit fixtures
---------------------------------------------------------
The engine unit tests (``tests/engines/security/test_firewall_analysis.py``)
prove each detector in isolation against minimal 1-2 rule inputs. This corpus is
**distinct and multi-rule**: realistic 4-8 rule policies modelled on the W2
``panos`` / ``fortios`` / cisco normalized outputs (the vendor ``any`` / ``all``
wildcard tokens, named zones like ``trust``/``untrust``, applications like
``web-browsing``, object names like ``web-servers``). It grades the *service as a
whole* — every analysis run over a full policy at once — so an interaction
between detectors (e.g. an overly-permissive rule that also shadows a later one)
is scored, not just a single hand-picked pair.

Grounding (corpus-drift risk, W5-T1 spec): fixtures use the exact normalized
field shapes the W2 plugins emit — PAN-OS ``<member>any</member>`` →
``("any",)``, FortiOS ``srcaddr: [{"name": "all"}]`` → ``("all",)`` (confirmed in
``tests/plugins/test_panos_conformance.py`` /
``tests/plugins/test_fortios_conformance.py``) — never a hand-guessed shape.

Secret hygiene (ADR-0033 §3 / ADR-0034 §2): every field here is firewall config
metadata — zone names, object names, CIDRs, service identities. No credential,
key, community string, or any secret material appears in any fixture; the
``description`` free-text fields carry only benign rule intent. The scorer
additionally asserts the *produced* findings are secret-free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network, ip_network
from uuid import UUID

from app.schemas.normalized import (
    AclAction,
    FirewallAction,
    NormalizedAclEntry,
    NormalizedFirewallRule,
)
from app.schemas.security import FindingCategory

# A stable, fixed device id and collection instant keep the corpus deterministic
# (no clock / uuid entropy enters a fixture — Exit criterion 4, reproducibility).
_DEVICE = UUID("22222222-2222-2222-2222-222222222222")
_COLLECTED_AT = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)


def _rule(
    name: str,
    *,
    vendor: str = "panos",
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
    """Build a corpus :class:`NormalizedFirewallRule` with stable provenance."""
    return NormalizedFirewallRule(
        device_id=_DEVICE,
        collected_at=_COLLECTED_AT,
        source_vendor=vendor,
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
    vendor: str = "cisco_ios",
    action: AclAction = AclAction.PERMIT,
    sequence: int | None = None,
    source: str | None = None,
    destination: str | None = None,
    source_is_any: bool = False,
    destination_is_any: bool = False,
) -> NormalizedAclEntry:
    """Build a corpus :class:`NormalizedAclEntry` with stable provenance.

    ``source`` / ``destination`` are given as CIDR strings for fixture ergonomics
    and parsed to the model's ``IPv4Network | IPv6Network`` type here (the W2
    parsers emit network objects, not strings).
    """

    def _net(value: str | None) -> IPv4Network | IPv6Network | None:
        return ip_network(value) if value is not None else None

    return NormalizedAclEntry(
        device_id=_DEVICE,
        collected_at=_COLLECTED_AT,
        source_vendor=vendor,
        acl_name=name,
        action=action,
        sequence=sequence,
        source=_net(source),
        destination=_net(destination),
        source_is_any=source_is_any,
        destination_is_any=destination_is_any,
    )


@dataclass(frozen=True)
class ExpectedFinding:
    """One ground-truth label: the W3 service must flag ``rule_name`` as ``category``.

    Identity is ``(category, rule_name)`` — the same key the scorer uses to match
    a produced :class:`~app.schemas.security.SecurityFinding`. We deliberately do
    NOT label on severity or rationale text: those are engine-internal narration
    the corpus must not couple to, so a severity-grading change never silently
    breaks the gate. Severity *floors* (a posture HIGH must stay HIGH) are checked
    separately by the engine unit suite, not scored here.

    ``rule_position`` is an OPTIONAL ACE-precise discriminator. It defaults to
    ``None``, in which case the scorer matches on ``(category, rule_name)`` alone —
    every existing firewall-rule label keeps that behaviour. When it is SET, the
    scorer additionally requires the produced finding's ``rule_position`` to equal
    it, so a label can pin one specific entry among several sharing a ``rule_name``.
    This matters where one ``acl_name``/``rule_name`` carries multiple entries (e.g.
    an ``OUTSIDE_IN`` ACL with a permit-any-any ACE at sequence 10 and a clean
    scoped ACE at sequence 20): without the position the gate would score a TP even
    if a regression flagged the WRONG entry. The W3 ACL-posture engine populates
    ``SecurityFinding.rule_position`` from the ACE ``sequence``
    (``app.engines.security.firewall._posture_acls``), so the position is an engine
    fact, not a fixture invention.
    """

    category: FindingCategory
    rule_name: str
    #: Optional ACE-precise position (an ACL ``sequence`` / a firewall ``position``).
    #: ``None`` -> match on ``(category, rule_name)`` only (the default for every
    #: non-positional label); when set, the produced finding's ``rule_position``
    #: MUST equal it for the label to score a true positive.
    rule_position: int | None = None


@dataclass(frozen=True)
class LabelledCase:
    """A labelled policy: input rules/ACLs + the findings the service must emit.

    ``rules`` is in policy evaluation order (top-down). ``expected`` is the
    complete ground-truth set for the two scored entry points combined
    (``analyze_firewall_rules`` ∪ ``analyze_security_posture``); a produced
    finding whose ``(category, rule_name)`` is not in ``expected`` is a false
    positive, and a missing one is a false negative.
    """

    name: str
    rules: tuple[NormalizedFirewallRule, ...]
    acls: tuple[NormalizedAclEntry, ...] = ()
    expected: frozenset[ExpectedFinding] = field(default_factory=frozenset)
    note: str = ""


_E = ExpectedFinding


# ---------------------------------------------------------------------------
# Cases. Each models a realistic multi-rule policy. Positives across all four
# classes; clean negatives so a flag-everything service fails precision.
# ---------------------------------------------------------------------------

CORPUS: tuple[LabelledCase, ...] = (
    # --- SHADOWED ------------------------------------------------------------
    LabelledCase(
        name="panos-deny-all-shadows-specific-allow",
        # A leading deny-any-any (PAN-OS `any` tokens) makes every later rule
        # unreachable. Both later allows are shadowed; the deny itself is clean.
        rules=(
            _rule(
                "block-everything",
                action=FirewallAction.DENY,
                position=0,
                source_zones=("any",),
                destination_zones=("any",),
                source_addresses=("any",),
                destination_addresses=("any",),
                applications=("any",),
                services=("any",),
                logging=True,
                description="Default deny placed too early by mistake",
            ),
            _rule(
                "allow-web",
                action=FirewallAction.ALLOW,
                position=1,
                source_zones=("trust",),
                destination_zones=("untrust",),
                source_addresses=("corp-net",),
                destination_addresses=("web-servers",),
                applications=("web-browsing",),
                services=("application-default",),
                logging=True,
            ),
            _rule(
                "allow-dns",
                action=FirewallAction.ALLOW,
                position=2,
                source_zones=("trust",),
                destination_zones=("untrust",),
                source_addresses=("corp-net",),
                destination_addresses=("dns-servers",),
                applications=("dns",),
                services=("application-default",),
                logging=True,
            ),
        ),
        expected=frozenset(
            {
                _E(FindingCategory.SHADOWED, "allow-web"),
                _E(FindingCategory.SHADOWED, "allow-dns"),
            }
        ),
        note="leading deny-any shadows every later rule (only first covering pred reported)",
    ),
    LabelledCase(
        name="fortios-allow-all-shadows-later-deny",
        # FortiOS `all` tokens: a permissive allow-all-all early kills a later
        # targeted deny — the deny is DEAD (a security gap). The allow-all is also
        # overly-permissive + (it logs) so it is not a posture-logging finding.
        rules=(
            _rule(
                "permit-outbound-any",
                vendor="fortios",
                action=FirewallAction.ALLOW,
                position=0,
                source_addresses=("all",),
                destination_addresses=("all",),
                services=("ALL",),
                logging=True,
                description="Broad outbound allow",
            ),
            _rule(
                "block-malware-c2",
                vendor="fortios",
                action=FirewallAction.DENY,
                position=1,
                source_addresses=("all",),
                destination_addresses=("threat-intel-c2",),
                services=("ALL",),
                logging=True,
            ),
        ),
        expected=frozenset(
            {
                _E(FindingCategory.SHADOWED, "block-malware-c2"),
                _E(FindingCategory.OVERLY_PERMISSIVE, "permit-outbound-any"),
            }
        ),
        note="dead deny behind allow-all (HIGH) + the allow-all is itself overly-permissive",
    ),
    # --- REDUNDANT -----------------------------------------------------------
    LabelledCase(
        name="panos-redundant-host-under-subnet",
        # A host rule fully covered by an earlier same-action subnet rule adds
        # nothing (zero hits) -> redundant. The covering subnet rule is clean.
        rules=(
            _rule(
                "allow-corp-subnet",
                action=FirewallAction.ALLOW,
                position=0,
                source_zones=("trust",),
                destination_zones=("dmz",),
                source_addresses=("corp-subnet-a", "corp-subnet-b"),
                destination_addresses=("app-tier",),
                applications=("ssl",),
                services=("application-default",),
                logging=True,
            ),
            _rule(
                "allow-corp-host",
                action=FirewallAction.ALLOW,
                position=1,
                source_zones=("trust",),
                destination_zones=("dmz",),
                source_addresses=("corp-subnet-a",),
                destination_addresses=("app-tier",),
                applications=("ssl",),
                services=("application-default",),
                logging=True,
                hit_count=0,
            ),
        ),
        expected=frozenset({_E(FindingCategory.REDUNDANT, "allow-corp-host")}),
        note="same-action subset rule is redundant; covering superset rule is clean",
    ),
    # --- OVERLY PERMISSIVE ---------------------------------------------------
    LabelledCase(
        name="panos-overly-permissive-mixed",
        # Three distinct exposure shapes alongside one clean least-privilege rule:
        #  - scoped src/dst but ANY service (MEDIUM overly-permissive),
        #  - a fully scoped allow (clean negative),
        #  - any->any allow (HIGH overly-permissive).
        # The any->any rule is placed LAST on purpose so it covers nothing earlier
        # and is not itself covered — this case scores the overly-permissive
        # detector in isolation, without an interacting redundant/shadow finding
        # (which the dedicated shadow/redundant cases already cover).
        rules=(
            _rule(
                "corp-to-db-any-service",
                action=FirewallAction.ALLOW,
                position=0,
                source_addresses=("corp-net",),
                destination_addresses=("db-tier",),
                services=(),  # any service
                logging=True,
            ),
            _rule(
                "allow-https-scoped",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("corp-net",),
                destination_addresses=("web-tier",),
                services=("https",),
                logging=True,
            ),
            _rule(
                "permit-any-any",
                action=FirewallAction.ALLOW,
                position=2,
                source_addresses=("any",),
                destination_addresses=("any",),
                services=("any",),
                logging=True,
                description="Temporary broad allow that was never removed",
            ),
        ),
        expected=frozenset(
            {
                _E(FindingCategory.OVERLY_PERMISSIVE, "permit-any-any"),
                _E(FindingCategory.OVERLY_PERMISSIVE, "corp-to-db-any-service"),
            }
        ),
        note="any-service (MEDIUM) + trailing any->any (HIGH); scoped rule is a clean negative",
    ),
    # --- POSTURE -------------------------------------------------------------
    LabelledCase(
        name="panos-posture-mgmt-and-logging",
        # Exercises both posture sub-checks plus the genuine cross-class overlap a
        # whole-policy scorer must capture:
        #  - SSH to a host from ANY source = exposed management plane (POSTURE HIGH)
        #    AND an any-source allow is, by definition, also OVERLY_PERMISSIVE — the
        #    same rule is correctly flagged by both detectors, and the ground truth
        #    labels both (suppressing either would be a labelling error).
        #  - a scoped allow with logging disabled = no audit trail (POSTURE MEDIUM).
        rules=(
            _rule(
                "mgmt-ssh-from-any",
                action=FirewallAction.ALLOW,
                position=0,
                source_addresses=("any",),
                destination_addresses=("core-switch-1",),
                services=("ssh",),
                logging=True,
                description="SSH jump access",
            ),
            _rule(
                "allow-web-no-log",
                action=FirewallAction.ALLOW,
                position=1,
                source_addresses=("corp-net",),
                destination_addresses=("web-tier",),
                services=("https",),
                logging=False,
                description="High-volume web rule, logging turned off",
            ),
        ),
        expected=frozenset(
            {
                _E(FindingCategory.POSTURE, "mgmt-ssh-from-any"),
                _E(FindingCategory.OVERLY_PERMISSIVE, "mgmt-ssh-from-any"),
                _E(FindingCategory.POSTURE, "allow-web-no-log"),
            }
        ),
        note="mgmt-from-any is both POSTURE-HIGH and OVERLY_PERMISSIVE; missing-log is POSTURE-MED",
    ),
    LabelledCase(
        name="cisco-acl-permit-any-any-posture",
        # An explicit permit any -> any ACE (both endpoints carry the literal-any
        # signal) is an unambiguous over-broad posture finding.
        rules=(),
        acls=(
            _acl(
                "OUTSIDE_IN",
                action=AclAction.PERMIT,
                sequence=10,
                source_is_any=True,
                destination_is_any=True,
            ),
            # A scoped permit ACE is a clean negative (must NOT be flagged).
            _acl(
                "OUTSIDE_IN",
                action=AclAction.PERMIT,
                sequence=20,
                source="10.0.0.0/24",
                destination="10.1.0.0/24",
            ),
        ),
        # ACE-precise label: the permit-any-any is at sequence 10, so the produced
        # POSTURE finding MUST carry rule_position=10. The clean scoped ACE shares
        # the acl_name OUTSIDE_IN at sequence 20 — pinning the position means a
        # regression that flagged seq-20 instead of seq-10 scores an FP+FN (the
        # label no longer matches the wrong ACE), so the gate drops below floor.
        expected=frozenset({_E(FindingCategory.POSTURE, "OUTSIDE_IN", rule_position=10)}),
        note="explicit any->any ACE (seq 10) is posture HIGH; scoped ACE (seq 20) is clean",
    ),
    # --- CLEAN NEGATIVES (precision guard) -----------------------------------
    LabelledCase(
        name="clean-least-privilege-policy",
        # A well-formed least-privilege policy: scoped allows + a trailing
        # default-deny. A flag-everything service fails precision here.
        rules=(
            _rule(
                "allow-web-https",
                action=FirewallAction.ALLOW,
                position=0,
                source_zones=("trust",),
                destination_zones=("dmz",),
                source_addresses=("corp-net",),
                destination_addresses=("web-tier",),
                applications=("ssl",),
                services=("https",),
                logging=True,
            ),
            _rule(
                "allow-dns-resolve",
                action=FirewallAction.ALLOW,
                position=1,
                source_zones=("trust",),
                destination_zones=("dmz",),
                source_addresses=("corp-net",),
                destination_addresses=("dns-tier",),
                applications=("dns",),
                services=("dns-udp",),
                logging=True,
            ),
            _rule(
                "default-deny",
                action=FirewallAction.DENY,
                position=2,
                source_addresses=("any",),
                destination_addresses=("any",),
                services=("any",),
                logging=True,
                description="Explicit default-deny (good hygiene)",
            ),
        ),
        expected=frozenset(),
        note="least-privilege allows + trailing default-deny: must produce zero findings",
    ),
    LabelledCase(
        name="clean-scoped-mgmt-from-jump-subnet",
        # Management SSH, but from a SPECIFIC jump subnet (not any) and logged:
        # neither the mgmt-exposure nor the logging posture check should fire.
        rules=(
            _rule(
                "mgmt-ssh-scoped",
                action=FirewallAction.ALLOW,
                position=0,
                source_addresses=("jump-subnet",),
                destination_addresses=("core-switch-1",),
                services=("ssh",),
                logging=True,
                description="SSH from the bastion subnet only",
            ),
        ),
        expected=frozenset(),
        note="scoped+logged mgmt access is clean (mgmt-exposure precision guard)",
    ),
)


def expected_by_class() -> dict[FindingCategory, int]:
    """Total ground-truth positives per finding class across the whole corpus."""
    counts: dict[FindingCategory, int] = {category: 0 for category in FindingCategory}
    for case in CORPUS:
        for label in case.expected:
            counts[label.category] += 1
    return counts


__all__ = [
    "CORPUS",
    "ExpectedFinding",
    "LabelledCase",
    "expected_by_class",
]
