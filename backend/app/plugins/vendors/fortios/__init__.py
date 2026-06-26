"""Fortinet FortiOS plugin (``vendor_id="fortios"``) — REST + netmiko SSH (ADR-0036).

Implements six capabilities, each using exactly one transport in P2:
``DISCOVERY_API``, ``INTERFACES``, ``ROUTES``, ``FIREWALL_POLICY``
(security + NAT rules, ADR-0034), and ``HA_STATUS`` are REST-only;
``CONFIG_BACKUP`` is SSH-only (``show full-configuration``). The cross-transport
fallbacks in the ADR-0036 §1 table are named-deferred until a follow-up ADR
wires them — an unreachable fallback would be the dead surface §1 warns against.

Auth via vault credential_ref for both REST token and SSH login (ADR-0011).
Raw-first on both transports (ADR-0006 §3). Read-only — no
``CONFIG_RESTORE`` / ``CONFIG_DEPLOY`` in P2 (ADR-0036 §5). Root VDOM only;
multi-VDOM deferred (ADR-0036 §4).
"""

from app.plugins.vendors.fortios.plugin import FortiosPlugin

__all__ = ["FortiosPlugin"]
