"""Discovery run planning (M1-12).

:class:`DiscoveryPlan` is the validated input of a discovery run (MVP §3:
"seed-expansion bounded by configurable hop limit and subnet allowlist").
Validation happens at construction so every downstream consumer (expansion,
Celery tasks in M1-14) can trust the plan: seeds are valid IP addresses
inside the allowlist, the allowlist is valid CIDR notation, and the hop
limit is non-negative.
"""

from __future__ import annotations

from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = ["DiscoveryPlan"]


class DiscoveryPlan(BaseModel):
    """The validated parameters of one discovery run.

    ``credential_names`` reference vault entries by name
    (``device_credentials``, D11) — never secret material.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", str_strip_whitespace=True)

    seeds: list[str] = Field(
        min_length=1,
        description="IP addresses of the seed devices (normalized canonical form).",
    )
    hop_limit: int = Field(
        ge=0,
        description="Maximum LLDP/CDP expansion hops from the seeds (0 = seeds only).",
    )
    allowlist: list[str] = Field(
        min_length=1,
        description="CIDR networks discovery may touch (canonical form).",
    )
    credential_names: list[str] = Field(
        default_factory=list,
        description="Vault credential names to try against discovered devices.",
    )

    @field_validator("seeds")
    @classmethod
    def _validate_seeds(cls, value: list[str]) -> list[str]:
        """Every seed must be a valid IP address; normalize to canonical form."""
        normalized: list[str] = []
        for raw in value:
            try:
                normalized.append(str(ip_address(raw)))
            except ValueError as exc:
                raise ValueError(f"seed {raw!r} is not a valid IP address") from exc
        return normalized

    @field_validator("allowlist")
    @classmethod
    def _validate_allowlist(cls, value: list[str]) -> list[str]:
        """Every allowlist entry must be valid CIDR notation; normalize."""
        normalized: list[str] = []
        for raw in value:
            try:
                normalized.append(str(ip_network(raw, strict=False)))
            except ValueError as exc:
                raise ValueError(f"allowlist entry {raw!r} is not a valid CIDR network") from exc
        return normalized

    @model_validator(mode="after")
    def _seeds_inside_allowlist(self) -> Self:
        """Every seed must fall inside at least one allowlist network."""
        for seed in self.seeds:
            if not self.is_allowed(seed):
                raise ValueError(f"seed {seed!r} is outside the allowlist")
        return self

    @property
    def allowed_networks(self) -> tuple[IPv4Network | IPv6Network, ...]:
        """The allowlist parsed into :mod:`ipaddress` network objects."""
        return tuple(ip_network(entry) for entry in self.allowlist)

    def is_allowed(self, target: str) -> bool:
        """Whether *target* (an IP address string) is inside the allowlist.

        Non-IP strings are never allowed — discovery only ever expands to
        addresses extracted from neighbor records.
        """
        try:
            addr = ip_address(target)
        except ValueError:
            return False
        return any(addr.version == net.version and addr in net for net in self.allowed_networks)
