"""Fortinet FortiOS plugin (``vendor_id="fortios"``) — REST + SSH fallback (ADR-0036).

Implements six capabilities with REST as primary transport and netmiko SSH as
fallback for the capabilities assigned to it by ADR-0036 §1:
``DISCOVERY_API``, ``INTERFACES``, ``ROUTES``, ``FIREWALL_POLICY``
(security + NAT rules, ADR-0034), ``CONFIG_BACKUP`` (SSH primary), and ``HA_STATUS``.

Auth via vault credential_ref for both REST token and SSH login (ADR-0011).
Raw-first on both transports (ADR-0006 §3). Read-only — no
``CONFIG_RESTORE`` / ``CONFIG_DEPLOY`` in P2 (ADR-0036 §5). Root VDOM only;
multi-VDOM deferred (ADR-0036 §4).
"""

from app.plugins.vendors.fortios.plugin import FortiosPlugin

__all__ = ["FortiosPlugin"]
