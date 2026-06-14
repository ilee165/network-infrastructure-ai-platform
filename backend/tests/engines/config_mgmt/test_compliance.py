"""Compliance engine + seeded policy pack (M4; ADR-0018).

Covers the contract the ADR fixes and the M4 exit criterion ("seeded policy
violation reported with device/rule/severity/evidence; compliant device clean"):

* the Pydantic policy schema validates well-formed policies and rejects
  malformed ones (unknown keys, bad regex, malformed assertions, duplicate
  rule ids);
* scope resolution skips (never passes) out-of-scope devices and an uncollected
  ``model_assert`` model;
* ``regex_present`` / ``regex_absent`` / ``model_assert`` evaluate deterministically
  with concrete evidence;
* the seeded ``baseline-hardening`` pack flags a hardening violation on a device
  with evidence and reports clean on a compliant device.

Pure, deterministic, LLM-free — no DB, no network, no Celery.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.engines.config_mgmt.compliance import (
    DeviceContext,
    FindingStatus,
    Policy,
    Severity,
    evaluate_policy,
    load_default_pack,
    load_policy_yaml,
)

# A device that satisfies every baseline-hardening rule.
COMPLIANT_CONFIG = "\n".join(
    [
        "hostname core-rtr-01",
        "!",
        "ip ssh version 2",
        "!",
        "ip access-list extended EDGE-IN",
        " permit tcp any any eq 443",
        " deny ip any any log",
        "!",
        "ntp server 10.0.0.1",
        "end",
    ]
)

# Same device, hardened-baseline violations introduced: no `ip ssh version 2`
# and a `permit ip any any` in the ACL.
NONCOMPLIANT_CONFIG = "\n".join(
    [
        "hostname core-rtr-01",
        "!",
        "ip ssh version 1",
        "!",
        "ip access-list extended EDGE-IN",
        " permit ip any any",
        "!",
        "ntp server 10.0.0.1",
        "end",
    ]
)


def _ctx(
    *,
    raw_config: str,
    vendor: str = "cisco_ios",
    role: str | None = "core",
    site: str | None = "hq",
    models: dict | None = None,
) -> DeviceContext:
    return DeviceContext(
        device_id=uuid4(),
        vendor=vendor,
        role=role,
        site=site,
        raw_config=raw_config,
        models=models or {"ntp_servers": ["10.0.0.1"]},
    )


# ---------------------------------------------------------------------------
# schema validation
# ---------------------------------------------------------------------------


def test_well_formed_policy_parses_with_discriminated_asserts() -> None:
    policy = load_policy_yaml(
        """
        id: p1
        version: 3
        scope: { vendors: [cisco_ios], roles: ["*"], sites: ["*"] }
        rules:
          - id: r-present
            severity: violation
            assert: { type: regex_present, pattern: '^ip ssh version 2$' }
          - id: r-absent
            severity: warn
            assert: { type: regex_absent, pattern: 'permit ip any any' }
          - id: r-model
            severity: info
            assert: { type: model_assert, model: ntp_servers, predicate: non_empty }
        """
    )
    assert isinstance(policy, Policy)
    assert policy.id == "p1"
    assert policy.version == 3
    assert [r.id for r in policy.rules] == ["r-present", "r-absent", "r-model"]
    assert policy.rules[0].severity is Severity.VIOLATION


def test_unknown_assert_type_is_rejected() -> None:
    with pytest.raises(ValidationError):
        load_policy_yaml(
            """
            id: p
            version: 1
            rules:
              - id: bad
                severity: info
                assert: { type: model_exists, model: x, predicate: non_empty }
            """
        )


def test_invalid_regex_pattern_is_rejected_at_load() -> None:
    with pytest.raises(ValidationError):
        load_policy_yaml(
            """
            id: p
            version: 1
            rules:
              - id: bad
                severity: info
                assert: { type: regex_present, pattern: '(' }
            """
        )


def test_unknown_top_level_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        load_policy_yaml(
            """
            id: p
            version: 1
            unexpected: true
            rules:
              - id: r
                severity: info
                assert: { type: regex_absent, pattern: 'x' }
            """
        )


def test_duplicate_rule_id_is_rejected() -> None:
    with pytest.raises(ValidationError):
        load_policy_yaml(
            """
            id: p
            version: 1
            rules:
              - id: dup
                severity: info
                assert: { type: regex_absent, pattern: 'a' }
              - id: dup
                severity: info
                assert: { type: regex_absent, pattern: 'b' }
            """
        )


def test_non_mapping_document_is_rejected() -> None:
    with pytest.raises(ValueError):
        load_policy_yaml("- just\n- a\n- list\n")


# ---------------------------------------------------------------------------
# scope resolution
# ---------------------------------------------------------------------------


def test_out_of_scope_device_is_skipped_not_passed() -> None:
    policy = load_policy_yaml(
        """
        id: p
        version: 1
        scope: { vendors: [eos], roles: ["*"], sites: ["*"] }
        rules:
          - id: r
            severity: violation
            assert: { type: regex_present, pattern: '^ip ssh version 2$' }
        """
    )
    findings = evaluate_policy(policy, _ctx(raw_config=COMPLIANT_CONFIG, vendor="cisco_ios"))
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.SKIPPED
    assert findings[0].status is not FindingStatus.PASS
    assert "scope" in findings[0].evidence


def test_wildcard_and_empty_scope_match_any_device() -> None:
    policy = load_policy_yaml(
        """
        id: p
        version: 1
        scope: { vendors: ["*"] }
        rules:
          - id: r
            severity: info
            assert: { type: regex_present, pattern: '^ip ssh version 2$' }
        """
    )
    findings = evaluate_policy(
        policy, _ctx(raw_config=COMPLIANT_CONFIG, vendor="juniper_junos", role=None, site=None)
    )
    assert findings[0].status is FindingStatus.PASS


def test_scope_matching_is_case_insensitive() -> None:
    policy = load_policy_yaml(
        """
        id: p
        version: 1
        scope: { vendors: [Cisco_IOS] }
        rules:
          - id: r
            severity: info
            assert: { type: regex_present, pattern: '^ip ssh version 2$' }
        """
    )
    findings = evaluate_policy(policy, _ctx(raw_config=COMPLIANT_CONFIG, vendor="cisco_ios"))
    assert findings[0].status is FindingStatus.PASS


# ---------------------------------------------------------------------------
# assertion evaluation
# ---------------------------------------------------------------------------


def test_regex_present_violation_carries_skip_reason_evidence() -> None:
    policy = load_policy_yaml(
        """
        id: p
        version: 1
        rules:
          - id: ssh
            severity: violation
            assert: { type: regex_present, pattern: '^ip ssh version 2$' }
        """
    )
    findings = evaluate_policy(policy, _ctx(raw_config=NONCOMPLIANT_CONFIG))
    assert findings[0].status is FindingStatus.VIOLATION
    assert "not found" in findings[0].evidence


def test_regex_absent_violation_quotes_the_offending_line() -> None:
    policy = load_policy_yaml(
        """
        id: p
        version: 1
        rules:
          - id: no-any-any
            severity: violation
            assert: { type: regex_absent, pattern: 'permit ip any any' }
        """
    )
    findings = evaluate_policy(policy, _ctx(raw_config=NONCOMPLIANT_CONFIG))
    assert findings[0].status is FindingStatus.VIOLATION
    assert "permit ip any any" in findings[0].evidence


def test_model_assert_non_empty_passes_and_empty_violates() -> None:
    policy = load_policy_yaml(
        """
        id: p
        version: 1
        rules:
          - id: ntp
            severity: warn
            assert: { type: model_assert, model: ntp_servers, predicate: non_empty }
        """
    )
    passing = evaluate_policy(
        policy, _ctx(raw_config=COMPLIANT_CONFIG, models={"ntp_servers": ["10.0.0.1"]})
    )
    assert passing[0].status is FindingStatus.PASS

    failing = evaluate_policy(policy, _ctx(raw_config=COMPLIANT_CONFIG, models={"ntp_servers": []}))
    assert failing[0].status is FindingStatus.VIOLATION


def test_model_assert_count_and_contains_predicates() -> None:
    policy = load_policy_yaml(
        """
        id: p
        version: 1
        rules:
          - id: ntp-count
            severity: info
            assert: { type: model_assert, model: ntp_servers, predicate: count_gte, value: 2 }
          - id: ntp-has-primary
            severity: info
            assert: { type: model_assert, model: ntp_servers, predicate: contains, value: 10.0.0.1 }
        """
    )
    findings = evaluate_policy(
        policy,
        _ctx(raw_config=COMPLIANT_CONFIG, models={"ntp_servers": ["10.0.0.1", "10.0.0.2"]}),
    )
    by_id = {f.rule_id: f for f in findings}
    assert by_id["ntp-count"].status is FindingStatus.PASS
    assert by_id["ntp-has-primary"].status is FindingStatus.PASS


def test_model_assert_uncollected_model_is_skipped_not_passed() -> None:
    policy = load_policy_yaml(
        """
        id: p
        version: 1
        rules:
          - id: bgp
            severity: warn
            assert: { type: model_assert, model: bgp_peers, predicate: non_empty }
        """
    )
    findings = evaluate_policy(
        policy, _ctx(raw_config=COMPLIANT_CONFIG, models={"ntp_servers": ["10.0.0.1"]})
    )
    assert findings[0].status is FindingStatus.SKIPPED
    assert findings[0].status is not FindingStatus.PASS
    assert "not collected" in findings[0].evidence


# ---------------------------------------------------------------------------
# seeded baseline-hardening pack (M4 exit criterion)
# ---------------------------------------------------------------------------


def test_seeded_pack_loads_and_has_expected_rules() -> None:
    policy = load_default_pack()
    assert policy.id == "baseline-hardening"
    rule_ids = {rule.id for rule in policy.rules}
    assert {"ssh-v2-only", "no-any-any-permit", "ntp-configured"} <= rule_ids


def test_seeded_pack_flags_violation_with_evidence() -> None:
    policy = load_default_pack()
    findings = evaluate_policy(
        policy,
        _ctx(raw_config=NONCOMPLIANT_CONFIG, models={"ntp_servers": ["10.0.0.1"]}),
    )
    by_id = {f.rule_id: f for f in findings}

    ssh = by_id["ssh-v2-only"]
    assert ssh.status is FindingStatus.VIOLATION
    assert ssh.severity is Severity.VIOLATION
    assert ssh.policy_id == "baseline-hardening"
    assert ssh.policy_version == 1
    assert ssh.evidence  # concrete evidence present

    acl = by_id["no-any-any-permit"]
    assert acl.status is FindingStatus.VIOLATION
    assert "permit ip any any" in acl.evidence


def test_seeded_pack_reports_compliant_device_clean() -> None:
    policy = load_default_pack()
    findings = evaluate_policy(
        policy,
        _ctx(raw_config=COMPLIANT_CONFIG, models={"ntp_servers": ["10.0.0.1"]}),
    )
    assert {f.rule_id for f in findings} == {
        "ssh-v2-only",
        "no-any-any-permit",
        "ntp-configured",
    }
    assert all(f.status is FindingStatus.PASS for f in findings)
    assert not any(f.status is FindingStatus.VIOLATION for f in findings)
