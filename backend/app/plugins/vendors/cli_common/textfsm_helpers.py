"""Shared TextFSM / ntc-templates coercion helpers for CLI vendors.

Platform-specific wrappers pass their ntc ``platform`` string into
:func:`parse_with_template`. Coercion helpers are intentionally vendor-agnostic.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import cast

from ntc_templates.parse import ParsingException, parse_output

from app.core.errors import PluginError
from app.schemas.normalized import InterfaceAdminStatus, InterfaceOperStatus

__all__ = [
    "address_or_none",
    "int_or_none",
    "parse_with_template",
    "statuses_from_link_protocol",
]


def parse_with_template(
    *,
    platform: str,
    command: str,
    raw_output: str,
    vendor_label: str,
) -> list[dict[str, str]]:
    """Run *raw_output* through the ntc-templates index for *command*/*platform*."""
    try:
        rows = parse_output(platform=platform, command=command, data=raw_output)
    except ParsingException as exc:
        raise PluginError(f"{vendor_label}: failed to parse output of {command!r}: {exc}") from exc
    return cast("list[dict[str, str]]", rows)


def int_or_none(value: object) -> int | None:
    """Coerce a TextFSM field to ``int``; empty/garbage fields become ``None``."""
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def address_or_none(value: object) -> IPv4Address | IPv6Address | None:
    """Coerce a TextFSM field to an IP address; empty/garbage become ``None``."""
    text = str(value).strip() if value is not None else ""
    if not text:
        return None
    try:
        return ip_address(text)
    except ValueError:
        return None


def statuses_from_link_protocol(
    link_status: str, protocol_status: str
) -> tuple[InterfaceAdminStatus, InterfaceOperStatus]:
    """Map ``<link>, line protocol is <proto>`` style fields to admin/oper."""
    admin = (
        InterfaceAdminStatus.DOWN
        if "administratively" in link_status.lower()
        else InterfaceAdminStatus.UP
    )
    proto = protocol_status.lower()
    if proto.startswith("up"):
        oper = InterfaceOperStatus.UP
    elif proto.startswith("down"):
        oper = InterfaceOperStatus.DOWN
    else:
        oper = InterfaceOperStatus.UNKNOWN
    return admin, oper
