"""Cisco IOS vendor plugin (``vendor_id="cisco_ios"``) — the reference plugin.

Implements DISCOVERY_SSH, DISCOVERY_SNMP, INTERFACES, ROUTES,
NEIGHBORS_LLDP, NEIGHBORS_CDP and CONFIG_BACKUP against the
:class:`~app.plugins.base.CommandTransport` /
:class:`~app.plugins.base.SnmpReadTransport` protocols (netmiko/pysnmp
backed in production, M1-08); CLI parsing uses ntc-templates/TextFSM
(platform key ``cisco_ios``, ADR-0007).
"""

from app.plugins.vendors.cisco_ios.plugin import CiscoIosPlugin

__all__ = ["CiscoIosPlugin"]
