"""Cisco IOS vendor plugin (``vendor_id="cisco_ios"``) — the M0 reference plugin.

Implements INTERFACES, ROUTES, NEIGHBORS_LLDP, NEIGHBORS_CDP and
CONFIG_BACKUP against the :class:`~app.plugins.base.CommandTransport`
protocol; parsing uses ntc-templates/TextFSM (platform key ``cisco_ios``,
ADR-0007). The netmiko-backed transport lands in M1.
"""

from app.plugins.vendors.cisco_ios.plugin import CiscoIosPlugin

__all__ = ["CiscoIosPlugin"]
