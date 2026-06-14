"""Server-side refresh-session service package (Auth & Account UI, B2).

Exposes the flush-only functions that manage :class:`RefreshSession` rows — the
durable, revocable record behind every refresh JWT (``sid`` claim).

    from app.services.auth_sessions import service as auth_sessions
"""

from app.services.auth_sessions.service import (
    create_session,
    get_live_session,
    revoke,
    revoke_all_for_user,
    touch,
)

__all__ = [
    "create_session",
    "get_live_session",
    "revoke",
    "revoke_all_for_user",
    "touch",
]
