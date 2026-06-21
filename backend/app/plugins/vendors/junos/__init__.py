"""Juniper JunOS vendor plugin (``vendor_id="junos"``) — ADR-0026.

Implements DISCOVERY_SSH, DISCOVERY_SNMP, INTERFACES, ROUTES,
NEIGHBORS_LLDP, BGP, OSPF, ACL (firewall filters), CONFIG_BACKUP,
CONFIG_RESTORE, and CONFIG_DEPLOY via the ADR-0007 netmiko
``juniper_junos`` transport with ``| display json`` structured output
(no CDP — JunOS does not speak CDP).  ADR-0021 config-write interfaces
are bound to JunOS native ``candidate config + commit confirmed + rollback N``.
"""

from app.plugins.vendors.junos.plugin import JunosPlugin

__all__ = ["JunosPlugin"]
