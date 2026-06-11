"""Cisco IOS-XE vendor plugin (``vendor_id="cisco_iosxe"``) — Cat9k/CSR/ISR.

Implements DISCOVERY_SSH, DISCOVERY_SNMP, INTERFACES, ROUTES,
NEIGHBORS_LLDP, NEIGHBORS_CDP and CONFIG_BACKUP against the
:class:`~app.plugins.base.CommandTransport` /
:class:`~app.plugins.base.SnmpReadTransport` protocols (netmiko/pysnmp
backed in production, M1-08); CLI parsing delegates to the
``cisco_ios`` parsers (ntc-templates platform key ``cisco_ios`` covers
IOS-XE show-output; ADR-0007).
"""

from app.plugins.vendors.cisco_iosxe.plugin import CiscoIosXePlugin

__all__ = ["CiscoIosXePlugin"]
