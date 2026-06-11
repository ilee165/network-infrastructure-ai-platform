"""Seed expansion (M1-12): the next wave of discovery targets.

Given the LLDP/CDP neighbors collected from the current wave of devices,
:func:`next_wave` computes which management addresses to visit next —
deduplicated, minus already-visited targets, and bounded by the subnet
allowlist (MVP §3). Hop counting is the caller's concern: the discovery
runner invokes ``next_wave`` once per hop until ``hop_limit`` is reached or
the wave is empty.
"""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from app.schemas.normalized import NormalizedNeighbor

__all__ = ["next_wave"]


def _canonical(value: str) -> str:
    """Canonical string form of an IP address; non-IP strings pass through."""
    try:
        return str(ip_address(value))
    except ValueError:
        return value


def next_wave(
    neighbors: list[NormalizedNeighbor],
    visited: set[str],
    allowlist: Iterable[str | IPv4Network | IPv6Network],
) -> list[str]:
    """Compute the next discovery targets from collected *neighbors*.

    Extracts each neighbor's management address (``neighbor_address``;
    neighbors without one cannot be expanded to and are dropped), dedupes
    while preserving first-seen order, and drops targets already in
    *visited* or outside *allowlist*.

    :param neighbors: neighbor records collected from the current wave.
    :param visited: addresses already visited (any parseable IP form).
    :param allowlist: CIDR strings or :mod:`ipaddress` network objects.
    :returns: canonical address strings to visit next, in first-seen order.
    """
    networks = tuple(
        net if isinstance(net, IPv4Network | IPv6Network) else ip_network(net, strict=False)
        for net in allowlist
    )
    seen = {_canonical(v) for v in visited}
    wave: list[str] = []
    for neighbor in neighbors:
        addr = neighbor.neighbor_address
        if addr is None:
            continue
        target = str(addr)
        if target in seen:
            continue
        if not any(addr.version == net.version and addr in net for net in networks):
            continue
        seen.add(target)
        wave.append(target)
    return wave
