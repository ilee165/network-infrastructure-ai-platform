"""SpatiumDDI vendor plugin (``vendor_id="spatiumddi"``) — self-hostable DDI.

Implements the four ADR-0022 DDI capability ABCs (DISCOVERY_API, DDI_DNS,
DDI_DHCP, DDI_IPAM) against the SpatiumDDI REST API over async httpx (ADR-0024).
Reads normalize to :mod:`app.schemas.normalized`; mutations return
:class:`~app.plugins.base.ChangeRequestDraft` objects and never write inline.
The REST client is vendor-private (ADR-0006 §6) — engines reach SpatiumDDI only
through the registry.

This package ships the REST client (ADR-0024 T3) plus the
:class:`~app.plugins.vendors.spatiumddi.plugin.SpatiumddiPlugin` and its four
capability implementations (ADR-0024 T4).
"""

from app.plugins.vendors.spatiumddi.plugin import SpatiumddiPlugin

__all__ = ["SpatiumddiPlugin"]
