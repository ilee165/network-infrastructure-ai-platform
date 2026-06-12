"""Discovery API contracts (M1-16): request/response models for ``/api/v1/discovery``.

Pure data (D2): validation only, no I/O. :class:`StartRunRequest` delegates
its semantic validation to :class:`~app.engines.discovery.planner.DiscoveryPlan`
so the API rejects (422) exactly what the discovery engine would reject —
invalid seed IPs, bad CIDR allowlists, seeds outside the allowlist — and the
stored run parameters are already in canonical form. Read models mirror the
:class:`~app.models.inventory.DiscoveryRun` ORM row via ``from_attributes``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.engines.discovery.planner import DiscoveryPlan
from app.models.inventory import DeviceStatus, DiscoveryRunStatus

__all__ = [
    "DiscoveredDeviceSummary",
    "RunListResponse",
    "RunResults",
    "RunStatus",
    "StartRunRequest",
]


class StartRunRequest(BaseModel):
    """Body of ``POST /discovery/runs``.

    Field shapes match :class:`DiscoveryPlan`; a model validator builds the
    plan eagerly so every constraint it enforces surfaces as a 422 problem
    instead of a failed Celery task, and ``seeds``/``allowlist`` come out
    canonicalized (e.g. ``2001:DB8::1`` → ``2001:db8::1``).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    seeds: list[str] = Field(min_length=1, description="IP addresses of the seed devices.")
    hop_limit: int = Field(
        ge=0, description="Maximum LLDP/CDP expansion hops from the seeds (0 = seeds only)."
    )
    allowlist: list[str] = Field(min_length=1, description="CIDR networks discovery may touch.")
    credential_names: list[str] = Field(
        default_factory=list,
        description="Vault credential names to try against discovered devices.",
    )

    @model_validator(mode="after")
    def _validate_as_plan(self) -> Self:
        """Reject anything :class:`DiscoveryPlan` would reject; canonicalize."""
        try:
            plan = self.to_plan()
        except ValidationError as exc:
            raise ValueError("; ".join(error["msg"] for error in exc.errors())) from exc
        self.seeds = list(plan.seeds)
        self.allowlist = list(plan.allowlist)
        return self

    def to_plan(self) -> DiscoveryPlan:
        """The validated :class:`DiscoveryPlan` these parameters describe."""
        return DiscoveryPlan(
            seeds=self.seeds,
            hop_limit=self.hop_limit,
            allowlist=self.allowlist,
            credential_names=self.credential_names,
        )


class RunStatus(BaseModel):
    """One discovery run as returned by the run endpoints."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: DiscoveryRunStatus
    seeds: list[str]
    hop_limit: int
    allowlist: list[str]
    credential_names: list[str]
    stats: dict[str, Any]
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class RunListResponse(BaseModel):
    """Paginated run collection (``GET /discovery/runs``), newest first."""

    items: list[RunStatus]
    total: int
    limit: int
    offset: int


class DiscoveredDeviceSummary(BaseModel):
    """One inventory device touched by a discovery run."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str
    mgmt_ip: str
    vendor_id: str | None
    status: DeviceStatus
    last_discovered_at: datetime | None


class RunResults(BaseModel):
    """Aggregated outcome of one run (``GET /discovery/runs/{id}/results``).

    Counts come from the normalized tables, scoped to the devices the run
    touched (devices referenced by the run's raw artifacts).
    """

    run_id: uuid.UUID
    status: DiscoveryRunStatus
    device_count: int
    interface_count: int
    route_count: int
    neighbor_count: int
    devices: list[DiscoveredDeviceSummary]
