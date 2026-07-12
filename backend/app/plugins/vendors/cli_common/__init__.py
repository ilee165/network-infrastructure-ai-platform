"""Shared CLI vendor helpers (Wave 3 T4 / AR-W2-T1 / H8).

Extracts the ADR-0021 write lifecycle and TextFSM coercion helpers that were
copy-pasted across ``cisco_ios`` / ``cisco_iosxe`` / ``cisco_nxos`` / ``eos`` /
``junos``. Import boundary matches vendor plugins: only ``app.core.errors`` and
``app.schemas.*`` / ``app.plugins.base`` — never services/engines.

Vendors are refit onto this package one commit at a time; behavioral
divergences found during refit are findings, not silent unifications.
"""

from app.plugins.vendors.cli_common.lifecycle import CliConfigWriteMixin
from app.plugins.vendors.cli_common.textfsm_helpers import (
    address_or_none,
    int_or_none,
    parse_with_template,
    statuses_from_link_protocol,
)

__all__ = [
    "CliConfigWriteMixin",
    "address_or_none",
    "int_or_none",
    "parse_with_template",
    "statuses_from_link_protocol",
]
