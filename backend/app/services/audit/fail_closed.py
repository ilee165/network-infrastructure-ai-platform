"""Shared fail-closed audit helper for KEK provider-unavailable events (H11).

When the KEK provider is unreachable the platform must still try to write a
``kek.provider.unavailable`` audit row — but an audit-path failure must **never**
mask the original :class:`~app.core.crypto.KeyProviderUnavailable`. Three call
sites (config archives, credential vault, rotation) previously drifted between
``except Exception: pass`` (silent) and unguarded writes (audit DB error
replaces the 503). This module is the single implementation.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from app.core.logging import get_logger

_logger = get_logger(__name__)

__all__ = ["audit_fail_closed"]


async def audit_fail_closed(
    write: Callable[[], Awaitable[None]],
    *,
    reason_class: str,
) -> None:
    """Run *write* (the audit emit); on any failure log and swallow.

    The caller's original fail-closed exception is preserved by the caller —
    this helper only protects the audit side-effect so a secondary audit DB
    error cannot replace a :class:`~app.core.crypto.KeyProviderUnavailable`.
    """
    try:
        await write()
    except Exception as audit_exc:  # noqa: BLE001 — never mask the original fail-closed error
        _logger.error(
            "kek.provider.unavailable.audit_failed",
            reason_class=reason_class,
            audit_error_class=type(audit_exc).__name__,
        )
