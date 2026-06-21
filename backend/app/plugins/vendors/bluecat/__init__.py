"""BlueCat Address Manager DDI plugin (``vendor_id="bluecat"``) — BAM RESTful v2.

Implements the four ADR-0022 DDI capability ABCs (DISCOVERY_API, DDI_DNS,
DDI_DHCP, DDI_IPAM) against the BAM RESTful v2 API (9.5+) over httpx (ADR-0027).
Reads normalize to :mod:`app.schemas.normalized`; mutations return
:class:`~app.plugins.base.ChangeRequestDraft` objects and never write inline.
The BAM client is vendor-private (ADR-0006 §6) — engines reach BlueCat only
through the registry.

The delete-inverse is a re-create from the captured prior body (hard delete;
no soft-delete / trash — ADR-0027 §3, explicitly NOT SpatiumDDI's RESTORE).
``object_ref`` = the BAM numeric entity ``id`` (stable, immutable PK).
"""

from app.plugins.vendors.bluecat.plugin import BluecatPlugin

__all__ = ["BluecatPlugin"]
