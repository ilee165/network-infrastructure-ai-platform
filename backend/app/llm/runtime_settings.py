"""DB-backed runtime resolution of the effective LLM profile per role (B5).

ADR-0009 fixes the role-indirection model: agents ask for a model by *role*
(``reasoning`` / ``fast``) and an operator maps each role to a profile. Env
``Settings`` supplies the defaults, but the Auth & Account UI lets an admin
persist overrides in the single ``system_settings`` row. This module is the
seam that consults that row **at runtime**, layering DB over env:

    role override (DB)  ->  base profile (DB)  ->  role override (env)  ->  base profile (env)

with each layer skipped when its value is null/absent. A deployment with no
row therefore resolves exactly as it does from env alone today.

Only the *profile choice* (``llm_profile`` and the role map) is DB-backed.
Provider API keys and the Ollama endpoint stay in env/``Settings`` and are
never read here — the resolver returns a profile name and nothing else, so no
secret can flow out of this path. The concrete model is still built by the
sync :func:`app.llm.providers.get_chat_model` factory.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.llm.providers import KNOWN_ROLES, LLMProfileError
from app.models.identity import SystemSetting

#: The role -> column map on the ``system_settings`` row, mirroring
#: ``Settings.llm_profile_for_role``. Kept here (not imported from the model) so
#: the resolver owns the role contract alongside :data:`KNOWN_ROLES`.
_ROLE_COLUMNS = {
    "reasoning": "llm_role_reasoning",
    "fast": "llm_role_fast",
}


async def _load_row(session: AsyncSession) -> SystemSetting | None:
    """Return the single ``system_settings`` row, or ``None`` when unset.

    The platform persists at most one settings row (admin-managed). If more
    than one somehow exists, the lowest-ordered row wins deterministically.
    """
    result = await session.execute(select(SystemSetting).order_by(SystemSetting.id).limit(1))
    return result.scalar_one_or_none()


async def effective_profile_for_role(
    session: AsyncSession,
    role: str,
    settings: Settings,
) -> str:
    """Resolve *role* to its effective LLM profile, preferring DB over env.

    Parameters
    ----------
    session:
        An :class:`AsyncSession` used only to read the ``system_settings`` row.
    role:
        One of :data:`app.llm.providers.KNOWN_ROLES`.
    settings:
        The env ``Settings`` providing the fallback profile + role map.

    Returns
    -------
    str
        The profile name to hand to :func:`app.llm.providers.get_chat_model`.
        Always one of the configured profiles when the stored data is valid
        (the PATCH endpoint validates writes); this resolver does not re-check
        profile validity so a hand-edited bad value surfaces at model-build
        time as the same :class:`LLMProfileError` it does today.

    Raises
    ------
    LLMProfileError
        When *role* is not a known role (matches the providers contract).
    """
    if role not in KNOWN_ROLES:
        raise LLMProfileError(f"unknown LLM role {role!r}; known roles: {', '.join(KNOWN_ROLES)}")

    row = await _load_row(session)
    if row is None:
        # No DB row: behave exactly as env-only resolution does today.
        return settings.llm_profile_for_role(role)

    db_role_override = getattr(row, _ROLE_COLUMNS[role])
    # DB role override wins; else the DB base profile. Env is consulted only
    # when the DB has nothing to say (no row at all, handled above).
    return db_role_override or row.llm_profile
