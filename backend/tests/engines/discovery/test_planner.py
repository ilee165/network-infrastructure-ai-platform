"""DiscoveryPlan validation matrix (M1-12 planner)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.engines.discovery.planner import DiscoveryPlan


def make_plan(**overrides: object) -> DiscoveryPlan:
    """Valid baseline plan; tests override single fields to probe validation."""
    kwargs: dict[str, object] = {
        "seeds": ["10.0.0.1"],
        "hop_limit": 2,
        "allowlist": ["10.0.0.0/24"],
        "credential_names": ["lab-ssh"],
    }
    kwargs.update(overrides)
    return DiscoveryPlan(**kwargs)  # type: ignore[arg-type]


class TestDiscoveryPlanValid:
    def test_baseline_plan_constructs(self) -> None:
        plan = make_plan()
        assert plan.seeds == ["10.0.0.1"]
        assert plan.hop_limit == 2
        assert plan.allowlist == ["10.0.0.0/24"]
        assert plan.credential_names == ["lab-ssh"]

    def test_hop_limit_zero_is_allowed(self) -> None:
        assert make_plan(hop_limit=0).hop_limit == 0

    def test_multiple_seeds_across_multiple_allowlist_networks(self) -> None:
        plan = make_plan(
            seeds=["10.0.0.1", "192.168.1.5"],
            allowlist=["10.0.0.0/24", "192.168.1.0/24"],
        )
        assert len(plan.seeds) == 2

    def test_ipv6_seed_inside_ipv6_allowlist(self) -> None:
        plan = make_plan(seeds=["2001:db8::1"], allowlist=["2001:db8::/64"])
        assert plan.seeds == ["2001:db8::1"]

    def test_seed_addresses_are_normalized(self) -> None:
        plan = make_plan(seeds=["2001:DB8:0:0::1"], allowlist=["2001:db8::/64"])
        assert plan.seeds == ["2001:db8::1"]

    def test_plan_is_frozen(self) -> None:
        plan = make_plan()
        with pytest.raises(ValidationError):
            plan.hop_limit = 99  # type: ignore[misc]


class TestDiscoveryPlanInvalid:
    def test_empty_seeds_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_plan(seeds=[])

    def test_empty_allowlist_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_plan(allowlist=[])

    def test_negative_hop_limit_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_plan(hop_limit=-1)

    def test_seed_that_is_not_an_ip_rejected(self) -> None:
        with pytest.raises(ValidationError, match="seed"):
            make_plan(seeds=["core-sw-01"])

    def test_invalid_cidr_rejected(self) -> None:
        with pytest.raises(ValidationError, match="CIDR"):
            make_plan(allowlist=["not-a-cidr"])

    def test_seed_outside_allowlist_rejected(self) -> None:
        with pytest.raises(ValidationError, match="allowlist"):
            make_plan(seeds=["172.16.0.1"])

    def test_one_bad_seed_among_good_ones_rejected(self) -> None:
        with pytest.raises(ValidationError, match="allowlist"):
            make_plan(seeds=["10.0.0.1", "172.16.0.1"])

    def test_ipv4_seed_not_inside_ipv6_only_allowlist(self) -> None:
        with pytest.raises(ValidationError, match="allowlist"):
            make_plan(seeds=["10.0.0.1"], allowlist=["2001:db8::/64"])


class TestIsAllowed:
    def test_address_inside_allowlist(self) -> None:
        assert make_plan().is_allowed("10.0.0.200") is True

    def test_address_outside_allowlist(self) -> None:
        assert make_plan().is_allowed("172.16.0.1") is False

    def test_non_ip_string_is_not_allowed(self) -> None:
        assert make_plan().is_allowed("not-an-ip") is False
