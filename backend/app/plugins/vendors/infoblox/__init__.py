"""Infoblox vendor plugin (``vendor_id="infoblox"``) — first API-based plugin.

Implements DISCOVERY_API, DDI_DNS, DDI_DHCP and DDI_IPAM against the Infoblox
WAPI REST API over httpx (no SSH/SNMP). Reads return normalized DDI/IPAM
records; mutations return :class:`~app.plugins.base.ChangeRequestDraft` objects
and never write to the appliance (ADR-0022). The WAPI client is vendor-private
(ADR-0006 §6) — engines reach Infoblox only through the registry.
"""

from app.plugins.vendors.infoblox.plugin import InfobloxPlugin

__all__ = ["InfobloxPlugin"]
