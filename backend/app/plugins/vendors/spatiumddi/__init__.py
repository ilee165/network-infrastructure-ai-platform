"""SpatiumDDI vendor plugin (``vendor_id="spatiumddi"``) — self-hostable DDI.

Implements the four ADR-0022 DDI capability ABCs (DISCOVERY_API, DDI_DNS,
DDI_DHCP, DDI_IPAM) against the SpatiumDDI REST API over async httpx (ADR-0024).
Reads normalize to :mod:`app.schemas.normalized`; mutations return
:class:`~app.plugins.base.ChangeRequestDraft` objects and never write inline.
The REST client is vendor-private (ADR-0006 §6) — engines reach SpatiumDDI only
through the registry.

This package currently ships the REST client (ADR-0024 T3); the capability
implementations + plugin land in the follow-on task.
"""
