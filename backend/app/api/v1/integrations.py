"""Integrations matrix — registered vendor plugins + declared capabilities.

``GET /api/v1/integrations`` is an admin Settings hub surface (Path B / T2.1).
It lists what the process-wide plugin registry can do — no live SSH/API
reachability checks (that is discovery, not Settings). Responses carry only
vendor ids, display names, capability names, and static category tags; never
credentials, connection params, or vault refs (ADR-0009 / ADR-0011).
"""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import enforce_api_rate_limit, require_role
from app.models import User
from app.plugins.registry import get_default_registry

router = APIRouter(
    prefix="/integrations",
    tags=["integrations"],
    dependencies=[Depends(enforce_api_rate_limit)],
)

#: Static category tags for known vendor ids (table in code, not DB). Unknown
#: vendors from third-party entry points get ``category="other"``.
VendorCategory = Literal["network", "ddi", "virt", "adc", "cloud", "other"]

_VENDOR_CATEGORY: dict[str, VendorCategory] = {
    "cisco_ios": "network",
    "cisco_iosxe": "network",
    "cisco_nxos": "network",
    "junos": "network",
    "eos": "network",
    "panos": "network",
    "fortios": "network",
    "f5_bigip": "adc",
    "bluecat": "ddi",
    "infoblox": "ddi",
    "spatiumddi": "ddi",
    "vmware": "virt",
    "aws": "cloud",
    "azure": "cloud",
    "route53": "cloud",
}


class IntegrationVendor(BaseModel):
    """One registered vendor plugin for the Settings integrations matrix."""

    vendor_id: str
    display_name: str
    capabilities: list[str] = Field(description="Sorted capability names this plugin declares")
    category: VendorCategory


class IntegrationsReport(BaseModel):
    """Registered plugins available to this API process."""

    vendors: list[IntegrationVendor]


@router.get("", response_model=IntegrationsReport)
async def list_integrations(
    admin: Annotated[User, Depends(require_role("admin"))],
) -> IntegrationsReport:
    """Return registered vendor plugins and their declared capabilities (admin).

    Read-only inventory for Settings → Integrations. Does not probe devices or
    open network connections. Capability sets come from the plugin class
    declarations via :meth:`PluginRegistry.capabilities_for`.
    """
    _ = admin  # role gate only
    registry = get_default_registry()
    vendors: list[IntegrationVendor] = []
    for vendor_id in registry.vendor_ids():
        plugin = registry.get_plugin(vendor_id)
        caps = sorted(c.value for c in registry.capabilities_for(vendor_id))
        vendors.append(
            IntegrationVendor(
                vendor_id=vendor_id,
                display_name=plugin.display_name,
                capabilities=caps,
                category=_VENDOR_CATEGORY.get(vendor_id, "other"),
            )
        )
    return IntegrationsReport(vendors=vendors)
