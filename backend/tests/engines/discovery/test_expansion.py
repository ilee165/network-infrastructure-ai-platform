"""next_wave seed-expansion behavior: extraction, dedupe, visited, allowlist."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from app.engines.discovery.expansion import next_wave
from app.schemas.normalized import NeighborProtocol, NormalizedNeighbor

ALLOWLIST = ["10.0.0.0/24", "2001:db8::/64"]


def make_neighbor(address: str | None, name: str = "nbr") -> NormalizedNeighbor:
    return NormalizedNeighbor(
        device_id=uuid4(),
        collected_at=datetime.now(UTC),
        source_vendor="cisco_ios",
        protocol=NeighborProtocol.LLDP,
        local_interface="Gi0/1",
        neighbor_name=name,
        neighbor_address=address,
    )


class TestNextWave:
    def test_extracts_allowed_addresses(self) -> None:
        neighbors = [make_neighbor("10.0.0.2"), make_neighbor("10.0.0.3")]
        assert next_wave(neighbors, set(), ALLOWLIST) == ["10.0.0.2", "10.0.0.3"]

    def test_drops_neighbors_without_mgmt_address(self) -> None:
        neighbors = [make_neighbor(None), make_neighbor("10.0.0.2")]
        assert next_wave(neighbors, set(), ALLOWLIST) == ["10.0.0.2"]

    def test_dedupes_preserving_first_seen_order(self) -> None:
        neighbors = [
            make_neighbor("10.0.0.3"),
            make_neighbor("10.0.0.2"),
            make_neighbor("10.0.0.3"),
        ]
        assert next_wave(neighbors, set(), ALLOWLIST) == ["10.0.0.3", "10.0.0.2"]

    def test_drops_visited_targets(self) -> None:
        neighbors = [make_neighbor("10.0.0.2"), make_neighbor("10.0.0.3")]
        assert next_wave(neighbors, {"10.0.0.2"}, ALLOWLIST) == ["10.0.0.3"]

    def test_drops_out_of_allowlist_targets(self) -> None:
        neighbors = [make_neighbor("172.16.0.1"), make_neighbor("10.0.0.2")]
        assert next_wave(neighbors, set(), ALLOWLIST) == ["10.0.0.2"]

    def test_ipv6_address_inside_ipv6_allowlist(self) -> None:
        neighbors = [make_neighbor("2001:db8::2")]
        assert next_wave(neighbors, set(), ALLOWLIST) == ["2001:db8::2"]

    def test_mixed_version_membership_does_not_crash(self) -> None:
        neighbors = [make_neighbor("2001:db8:ffff::1")]
        # only an IPv4 allowlist: the IPv6 neighbor is simply excluded
        assert next_wave(neighbors, set(), ["10.0.0.0/24"]) == []

    def test_empty_neighbor_list_yields_empty_wave(self) -> None:
        assert next_wave([], set(), ALLOWLIST) == []

    def test_visited_entries_in_non_canonical_form_still_match(self) -> None:
        neighbors = [make_neighbor("2001:db8::2")]
        assert next_wave(neighbors, {"2001:DB8:0:0::2"}, ALLOWLIST) == []

    def test_all_filtered_yields_empty_wave(self) -> None:
        neighbors = [make_neighbor("10.0.0.2"), make_neighbor("172.16.0.1")]
        assert next_wave(neighbors, {"10.0.0.2"}, ALLOWLIST) == []
