"""POST /auth/refresh reuse detection (audit PRODUCTION_READINESS #5, migration 0015).

A refresh presenting a rotated-out (stale) ``jti`` is a theft signal: the
session is revoked in the same request, ``auth.refresh_reuse_detected`` is
audited (jti hash only — never token material), and the generic 401 is
returned. Legitimate rotation — including the pre-0015 NULL-hash backfill and
the single-flight rapid-refresh pattern — is unaffected.
"""

from __future__ import annotations

import hashlib
import uuid

import httpx
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings
from app.models import AuditLog, RefreshSession, User
from tests.api.conftest import TEST_PASSWORD

LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"
REFRESH_COOKIE = "netops_refresh"
REUSE_ACTION = "auth.refresh_reuse_detected"


def _decode(token: str, settings: Settings) -> dict:
    return jwt.decode(token, settings.secret_key, algorithms=["HS256"])


async def _login(client: httpx.AsyncClient, username: str = "engineer_user") -> httpx.Response:
    resp = await client.post(LOGIN_URL, json={"username": username, "password": TEST_PASSWORD})
    assert resp.status_code == 200
    return resp


async def _refresh_with(client: httpx.AsyncClient, token: str) -> httpx.Response:
    """POST /auth/refresh presenting exactly *token* (attacker-style replay).

    The jar is cleared and the cookie sent as an explicit header so the request
    carries ONLY the replayed token — never the jar's current (rotated) cookie.
    """
    client.cookies.clear()
    return await client.post(REFRESH_URL, headers={"cookie": f"{REFRESH_COOKIE}={token}"})


async def _get_session_row(session: AsyncSession, sid: uuid.UUID) -> RefreshSession:
    row = (
        await session.execute(select(RefreshSession).where(RefreshSession.id == sid))
    ).scalar_one_or_none()
    assert row is not None
    return row


# ---------------------------------------------------------------------------
# Theft signal: stale (rotated-out) jti
# ---------------------------------------------------------------------------


async def test_stale_jti_returns_401_revokes_session_and_audits(
    client: httpx.AsyncClient,
    users: dict[str, User],
    session: AsyncSession,
    settings: Settings,
) -> None:
    login_resp = await _login(client)
    stolen_token = login_resp.cookies[REFRESH_COOKIE]
    stolen_claims = _decode(stolen_token, settings)
    sid = uuid.UUID(stolen_claims["sid"])

    # Legitimate rotation supersedes the stolen copy.
    rotate_resp = await client.post(REFRESH_URL)
    assert rotate_resp.status_code == 200

    # Attacker replays the rotated-out cookie.
    replay_resp = await _refresh_with(client, stolen_token)

    assert replay_resp.status_code == 401
    assert replay_resp.json()["type"] == "urn:netops:error:unauthorized"
    assert "access_token" not in replay_resp.text

    # The whole session is dead: even the legitimate (rotated) cookie is out.
    row = await _get_session_row(session, sid)
    assert row.revoked_at is not None

    rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == REUSE_ACTION)))
        .scalars()
        .all()
    )
    assert len(rows) == 1
    audit = rows[0]
    assert audit.actor == "user:engineer_user"
    assert audit.target_type == "refresh_session"
    assert audit.target_id == str(sid)
    assert audit.detail == {
        "presented_jti_hash": hashlib.sha256(stolen_claims["jti"].encode()).hexdigest(),
        "outcome": "session_revoked",
    }
    # No token material in the audit payload — hash/ids only.
    assert stolen_token not in str(audit.detail)
    assert stolen_claims["jti"] not in str(audit.detail)


async def test_after_reuse_detection_the_rotated_cookie_is_also_dead(
    client: httpx.AsyncClient, users: dict[str, User], settings: Settings
) -> None:
    login_resp = await _login(client)
    stolen_token = login_resp.cookies[REFRESH_COOKIE]

    rotate_resp = await client.post(REFRESH_URL)
    current_token = rotate_resp.cookies[REFRESH_COOKIE]

    assert (await _refresh_with(client, stolen_token)).status_code == 401

    # The victim's current (legitimate) cookie now names a revoked session.
    assert (await _refresh_with(client, current_token)).status_code == 401


# ---------------------------------------------------------------------------
# Legitimate rotation is unaffected
# ---------------------------------------------------------------------------


async def test_login_persists_current_jti_hash(
    client: httpx.AsyncClient,
    users: dict[str, User],
    session: AsyncSession,
    settings: Settings,
) -> None:
    login_resp = await _login(client)
    claims = _decode(login_resp.cookies[REFRESH_COOKIE], settings)

    row = await _get_session_row(session, uuid.UUID(claims["sid"]))
    assert row.current_jti_hash == hashlib.sha256(claims["jti"].encode()).hexdigest()
    # The hash never equals the jti or the token itself (no material at rest).
    assert row.current_jti_hash != claims["jti"]


async def test_rotation_updates_current_jti_hash_and_stays_live(
    client: httpx.AsyncClient,
    users: dict[str, User],
    session: AsyncSession,
    settings: Settings,
) -> None:
    login_resp = await _login(client)
    login_claims = _decode(login_resp.cookies[REFRESH_COOKIE], settings)
    sid = uuid.UUID(login_claims["sid"])

    refresh_resp = await client.post(REFRESH_URL)
    assert refresh_resp.status_code == 200
    rotated_claims = _decode(refresh_resp.cookies[REFRESH_COOKIE], settings)
    assert rotated_claims["sid"] == str(sid)
    assert rotated_claims["jti"] != login_claims["jti"]

    row = await _get_session_row(session, sid)
    await session.refresh(row)
    assert row.revoked_at is None
    assert row.current_jti_hash == hashlib.sha256(rotated_claims["jti"].encode()).hexdigest()


async def test_rapid_sequential_refreshes_do_not_false_trip_reuse_detection(
    client: httpx.AsyncClient,
    users: dict[str, User],
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Two rapid refreshes under the frontend single-flight assumption.

    The Wave 2 item-2 single-flight guard serializes browser refreshes, so the
    server sees back-to-back rotations, each presenting the latest cookie —
    which must NOT be flagged as reuse. (The residual truly-concurrent race
    window — both requests reading the stored hash before either commits — is
    documented on the endpoint; it fails closed to a re-login, never an access
    grant, and is unreachable while the single-flight guard holds.)
    """
    login_resp = await _login(client)
    sid = uuid.UUID(_decode(login_resp.cookies[REFRESH_COOKIE], settings)["sid"])

    first = await client.post(REFRESH_URL)
    second = await client.post(REFRESH_URL)
    assert first.status_code == 200
    assert second.status_code == 200

    row = await _get_session_row(session, sid)
    assert row.revoked_at is None
    reuse_rows = (
        (await session.execute(select(AuditLog).where(AuditLog.action == REUSE_ACTION)))
        .scalars()
        .all()
    )
    assert reuse_rows == []


# ---------------------------------------------------------------------------
# Pre-0015 sessions: NULL hash is accepted once and backfilled
# ---------------------------------------------------------------------------


async def test_null_hash_legacy_session_refreshes_and_backfills(
    client: httpx.AsyncClient,
    users: dict[str, User],
    session: AsyncSession,
    settings: Settings,
) -> None:
    login_resp = await _login(client)
    sid = uuid.UUID(_decode(login_resp.cookies[REFRESH_COOKIE], settings)["sid"])

    # Simulate a session created before migration 0015 (no reuse baseline).
    row = await _get_session_row(session, sid)
    row.current_jti_hash = None
    await session.commit()

    refresh_resp = await client.post(REFRESH_URL)
    assert refresh_resp.status_code == 200

    await session.refresh(row)
    assert row.revoked_at is None
    rotated_claims = _decode(refresh_resp.cookies[REFRESH_COOKIE], settings)
    assert row.current_jti_hash == hashlib.sha256(rotated_claims["jti"].encode()).hexdigest()


async def test_refresh_token_without_jti_claim_is_rejected_without_revocation(
    client: httpx.AsyncClient,
    users: dict[str, User],
    session: AsyncSession,
    settings: Settings,
) -> None:
    """A signed refresh token missing ``jti`` is malformed (we always mint one).

    It is rejected with the generic 401 but is NOT treated as theft: no
    issuance path produces such a token, so there is no rotation baseline to
    have violated — revoking would let a bug DoS the session.
    """
    from app.core.security import create_access_token

    login_resp = await _login(client)
    claims = _decode(login_resp.cookies[REFRESH_COOKIE], settings)
    sid = uuid.UUID(claims["sid"])
    forged = create_access_token(
        claims["sub"],
        settings,
        extra_claims={"type": "refresh", "sid": str(sid)},
    )
    resp = await _refresh_with(client, forged)
    assert resp.status_code == 401

    row = await _get_session_row(session, sid)
    assert row.revoked_at is None
