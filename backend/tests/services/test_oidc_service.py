"""ADR-0028 §2/§4/§6 OIDC service: deny-default mapping + JIT 1:1 provisioning.

Covers the deny-default role map (no implicit role for unmapped/groupless
users; admin-cap unless opted in), JIT provisioning anchored on the immutable
``(idp_iss, idp_subject)`` pair, per-login role re-derivation (roles never
sticky), and the 1:1 anchor (re-login reuses the same row, never a second).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.security import Role as RoleEnum
from app.models import AuditLog, Base, Role, User
from app.services import oidc as oidc_service
from app.services.oidc import map_groups_to_role
from app.services.oidc.mapping import RoleMappingError

GROUP_MAP = {
    "netops-viewers": "viewer",
    "netops-ops": "operator",
    "netops-engineers": "engineer",
    "netops-admins": "admin",
}


@pytest.fixture()
async def roles(session: AsyncSession) -> dict[str, Role]:
    rows = {name: Role(name=name) for name in ("viewer", "operator", "engineer", "admin")}
    session.add_all(rows.values())
    await session.flush()
    return rows


# ---------------------------------------------------------------------------
# Deny-default group → role mapping (§4)
# ---------------------------------------------------------------------------


def test_no_groups_claim_denies() -> None:
    assert map_groups_to_role(None, GROUP_MAP, allow_admin=False) is None


def test_empty_groups_denies() -> None:
    assert map_groups_to_role([], GROUP_MAP, allow_admin=False) is None


def test_unmapped_group_denies() -> None:
    assert map_groups_to_role(["unknown-group"], GROUP_MAP, allow_admin=False) is None


def test_mapped_group_resolves_role() -> None:
    assert (
        map_groups_to_role(["netops-engineers"], GROUP_MAP, allow_admin=False) is RoleEnum.ENGINEER
    )


def test_multiple_groups_collapse_to_highest() -> None:
    role = map_groups_to_role(
        ["netops-viewers", "netops-engineers", "netops-ops"], GROUP_MAP, allow_admin=False
    )
    assert role is RoleEnum.ENGINEER


def test_admin_capped_at_engineer_unless_opted_in() -> None:
    # allow_admin False: an admin group is capped at engineer (break-glass-only).
    assert map_groups_to_role(["netops-admins"], GROUP_MAP, allow_admin=False) is RoleEnum.ENGINEER
    # allow_admin True: OIDC may grant admin.
    assert map_groups_to_role(["netops-admins"], GROUP_MAP, allow_admin=True) is RoleEnum.ADMIN


def test_bad_role_name_in_map_raises() -> None:
    with pytest.raises(RoleMappingError):
        map_groups_to_role(["g"], {"g": "superuser"}, allow_admin=True)


# ---------------------------------------------------------------------------
# JIT provisioning + identity anchoring (§2/§6)
# ---------------------------------------------------------------------------


async def test_first_login_provisions_user_row(
    session: AsyncSession, roles: dict[str, Role]
) -> None:
    user = await oidc_service.provision_or_link_user(
        session,
        idp_iss="https://idp",
        idp_subject="sub-1",
        role=RoleEnum.ENGINEER,
        email="a@x.com",
        display_name="Alice",
    )
    assert user.idp_iss == "https://idp"
    assert user.idp_subject == "sub-1"
    assert user.role.name == "engineer"
    assert user.email == "a@x.com"
    # JIT-provision is audited.
    actions = {r.action for r in (await session.execute(select(AuditLog))).scalars().all()}
    assert "auth.oidc.user_provisioned" in actions
    assert "auth.oidc.role_mapped" in actions


async def test_relogin_reuses_same_row_and_redives_role(
    session: AsyncSession, roles: dict[str, Role]
) -> None:
    first = await oidc_service.provision_or_link_user(
        session,
        idp_iss="https://idp",
        idp_subject="sub-1",
        role=RoleEnum.VIEWER,
        email="a@x.com",
        display_name="Alice",
    )
    await session.commit()
    first_id = first.id

    # Same identity logs in again, now mapped to a higher role + changed email.
    second = await oidc_service.provision_or_link_user(
        session,
        idp_iss="https://idp",
        idp_subject="sub-1",
        role=RoleEnum.ENGINEER,
        email="alice@new.com",
        display_name="Alice New",
    )
    await session.commit()

    # One federated identity ⇒ exactly one row (§6): same id, not a new user.
    assert second.id == first_id
    rows = (await session.execute(select(User).where(User.idp_subject == "sub-1"))).scalars().all()
    assert len(rows) == 1
    # Role re-derived (never sticky) and display claims refreshed.
    assert second.role.name == "engineer"
    assert second.email == "alice@new.com"


async def test_distinct_subjects_get_distinct_rows(
    session: AsyncSession, roles: dict[str, Role]
) -> None:
    u1 = await oidc_service.provision_or_link_user(
        session,
        idp_iss="https://idp",
        idp_subject="sub-1",
        role=RoleEnum.VIEWER,
        email=None,
        display_name=None,
    )
    u2 = await oidc_service.provision_or_link_user(
        session,
        idp_iss="https://idp",
        idp_subject="sub-2",
        role=RoleEnum.VIEWER,
        email=None,
        display_name=None,
    )
    await session.commit()
    assert u1.id != u2.id


async def test_unique_constraint_blocks_duplicate_anchor(
    session: AsyncSession, roles: dict[str, Role]
) -> None:
    """The DB-level partial UNIQUE index is the backstop (§6)."""
    from sqlalchemy.exc import IntegrityError

    session.add(
        User(
            username="oidc_a",
            password_hash="!oidc",
            role=roles["viewer"],
            idp_iss="https://idp",
            idp_subject="dup",
        )
    )
    session.add(
        User(
            username="oidc_b",
            password_hash="!oidc",
            role=roles["viewer"],
            idp_iss="https://idp",
            idp_subject="dup",
        )
    )
    with pytest.raises(IntegrityError):
        await session.flush()


async def test_concurrent_first_login_race_recovers_via_integrity_error() -> None:
    """Two callbacks for one (iss, sub) race the unique anchor; the loser recovers.

    Uses a shared-cache SQLite DB so a SEPARATE connection can act as the
    concurrent "winner". The loser's pre-insert lookup misses, then — inside the
    flush — the winner commits its anchor on the other connection, so the loser's
    flush raises IntegrityError. The service must roll back, re-select the
    winner, update it, and return it: one identity ⇒ one row, login still works.
    """
    # A named shared-cache in-memory DB: every connection sees the same data.
    dsn = f"sqlite+aiosqlite:///file:race_{uuid.uuid4().hex}?mode=memory&cache=shared&uri=true"
    engine = create_async_engine(dsn)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with maker() as setup:
            viewer = Role(name="viewer")
            # 'engineer' must exist so the recovery path's role re-derivation can
            # resolve RoleEnum.ENGINEER for the winning row.
            setup.add_all([viewer, Role(name="engineer")])
            await setup.commit()
            viewer_id = viewer.id

        state = {"raised": False}
        winner_holder: dict[str, object] = {}

        async with maker() as loser:
            real_flush = loser.flush

            async def flaky_flush(*args: object, **kwargs: object) -> None:
                # First flush = our losing INSERT. Mimic the concurrent winner
                # committing its anchor in the race window (separate session),
                # then raise IntegrityError as the real unique collision would.
                if not state["raised"]:
                    state["raised"] = True
                    async with maker() as winner_session:
                        win = User(
                            username="oidc_winner",
                            password_hash="!oidc",
                            role_id=viewer_id,
                            idp_iss="https://idp",
                            idp_subject="race-sub",
                        )
                        winner_session.add(win)
                        await winner_session.flush()
                        winner_holder["id"] = win.id
                        await winner_session.commit()
                    raise IntegrityError("INSERT users", {}, Exception("unique"))
                await real_flush(*args, **kwargs)

            loser.flush = flaky_flush  # type: ignore[method-assign]
            user = await oidc_service.provision_or_link_user(
                loser,
                idp_iss="https://idp",
                idp_subject="race-sub",
                role=RoleEnum.ENGINEER,
                email="raced@x.com",
                display_name="Raced",
            )
            loser.flush = real_flush  # type: ignore[method-assign]
            await loser.commit()

            # Recovered onto the winner row (same id); role re-derived, claims set.
            assert user.id == winner_holder["id"]
            assert user.role.name == "engineer"
            assert user.email == "raced@x.com"
            rows = (
                (await loser.execute(select(User).where(User.idp_subject == "race-sub")))
                .scalars()
                .all()
            )
            assert len(rows) == 1
    finally:
        await engine.dispose()


async def test_local_users_with_null_anchor_coexist(
    session: AsyncSession, roles: dict[str, Role]
) -> None:
    """The partial index exempts local users (NULL anchor)."""
    session.add(User(username="local_a", password_hash="h", role=roles["viewer"]))
    session.add(User(username="local_b", password_hash="h", role=roles["viewer"]))
    await session.flush()  # no IntegrityError
    rows = (await session.execute(select(User))).scalars().all()
    assert len([r for r in rows if r.idp_subject is None]) == 2


def test_resolve_display_claims_prefers_email_and_name() -> None:
    email, name = oidc_service.resolve_display_claims(
        {"email": "e@x.com", "name": "Full Name", "sub": "s"}
    )
    assert email == "e@x.com"
    assert name == "Full Name"


def test_resolve_display_claims_falls_back_to_preferred_username() -> None:
    email, name = oidc_service.resolve_display_claims({"preferred_username": "alice", "sub": "s"})
    assert email is None
    assert name == "alice"
