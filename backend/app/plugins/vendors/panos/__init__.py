"""Palo Alto PAN-OS plugin (``vendor_id="panos"``) — XML API firewall (ADR-0035).

Implements six capabilities over the PAN-OS XML API (HTTPS/httpx, ADR-0007 D7):
``DISCOVERY_API``, ``INTERFACES``, ``ROUTES``, ``FIREWALL_POLICY``
(security + NAT rules, ADR-0034), ``CONFIG_BACKUP``, and ``HA_STATUS``.

Auth via vault API key (ADR-0011 ``credential_ref``); raw-first (ADR-0006 §3).
Read-only — no ``CONFIG_RESTORE`` / ``CONFIG_DEPLOY`` in P2 (ADR-0035 §6).
Single firewall-local policy on default vsys1; Panorama/multi-vsys deferred
(ADR-0035 §5). The PAN-OS client is vendor-private (ADR-0006 §6) — engines
reach PAN-OS only through the registry.
"""

from app.plugins.vendors.panos.plugin import PanosPlugin

__all__ = ["PanosPlugin"]
