"""Append-only audit writer: persistence, transaction ownership, structlog event."""

from __future__ import annotations

import uuid
from datetime import UTC

import structlog.testing
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog
from app.services.audit import service as audit_service


async def test_record_persists_row_with_fields_intact(session: AsyncSession) -> None:
    """`record` inserts a row whose columns match the arguments exactly."""
    target_id = str(uuid.uuid4())
    entry = await audit_service.record(
        session,
        actor="user:alice",
        action=audit_service.DEVICE_CREATED,
        target_type="device",
        target_id=target_id,
        detail=None,
    )

    reloaded = (
        await session.execute(
            select(AuditLog)
            .where(AuditLog.id == entry.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.actor == "user:alice"
    assert reloaded.action == "device.created"
    assert reloaded.target_type == "device"
    assert reloaded.target_id == target_id
    assert reloaded.detail is None
    assert reloaded.created_at.tzinfo == UTC


async def test_record_detail_dict_roundtrips(session: AsyncSession) -> None:
    """A nested JSON detail payload survives the insert/reload cycle intact."""
    detail = {
        "before": {"status": "new"},
        "after": {"status": "reachable"},
        "counts": [1, 2, 3],
    }
    entry = await audit_service.record(
        session,
        actor="system:discovery",
        action=audit_service.DISCOVERY_RUN_FINISHED,
        target_type="discovery_run",
        target_id="42",
        detail=detail,
    )

    reloaded = (
        await session.execute(
            select(AuditLog)
            .where(AuditLog.id == entry.id)
            .execution_options(populate_existing=True)
        )
    ).scalar_one()
    assert reloaded.detail == detail


async def test_record_flushes_but_does_not_commit(session: AsyncSession) -> None:
    """The caller owns the transaction: a rollback discards the audit row."""
    await audit_service.record(
        session,
        actor="user:bob",
        action=audit_service.AUTH_LOGIN,
        target_type="user",
        target_id=None,
        detail=None,
    )
    assert session.in_transaction()
    await session.rollback()

    count = (await session.execute(select(func.count()).select_from(AuditLog))).scalar_one()
    assert count == 0


async def test_record_emits_one_structlog_info_event(session: AsyncSession) -> None:
    """Exactly one info-level structlog event carries the audited fields."""
    detail = {"reason": "rotation schedule"}
    with structlog.testing.capture_logs() as captured:
        entry = await audit_service.record(
            session,
            actor="user:carol",
            action=audit_service.CREDENTIAL_ROTATED,
            target_type="credential",
            target_id="cred-7",
            detail=detail,
        )

    assert len(captured) == 1
    event = captured[0]
    assert event["log_level"] == "info"
    assert event["actor"] == "user:carol"
    assert event["action"] == "credential.rotated"
    assert event["target_type"] == "credential"
    assert event["target_id"] == "cred-7"
    assert event["detail"] == detail
    assert event["audit_id"] == str(entry.id)


def test_m1_action_name_constants() -> None:
    """The M1 action vocabulary is fixed; routes and engines reuse these names."""
    assert audit_service.CREDENTIAL_CREATED == "credential.created"
    assert audit_service.CREDENTIAL_ROTATED == "credential.rotated"
    assert audit_service.CREDENTIAL_DECRYPTED == "credential.decrypted"
    assert audit_service.DEVICE_CREATED == "device.created"
    assert audit_service.DEVICE_UPDATED == "device.updated"
    assert audit_service.DEVICE_DELETED == "device.deleted"
    assert audit_service.DISCOVERY_RUN_STARTED == "discovery.run_started"
    assert audit_service.DISCOVERY_RUN_FINISHED == "discovery.run_finished"
    assert audit_service.AUTH_LOGIN == "auth.login"
    assert audit_service.AUTH_REFRESH == "auth.refresh"


def test_auth_account_action_name_constants() -> None:
    """The Auth & Account UI action vocabulary (B1) is fixed and importable."""
    assert audit_service.AUTH_LOGOUT == "auth.logout"
    assert audit_service.AUTH_LOGIN_FAILED == "auth.login_failed"
    assert audit_service.AUTH_PASSWORD_CHANGED == "auth.password_changed"
    assert audit_service.AUTH_SESSION_REVOKED == "auth.session_revoked"
    assert audit_service.USER_CREATED == "user.created"
    assert audit_service.USER_UPDATED == "user.updated"
    assert audit_service.USER_ROLE_CHANGED == "user.role_changed"
    assert audit_service.USER_PASSWORD_RESET == "user.password_reset"
    assert audit_service.SETTINGS_UPDATED == "settings.updated"


def test_auth_account_constants_reexported_from_package() -> None:
    """The B1 constants are also re-exported from the audit package root."""
    from app.services import audit

    assert audit.AUTH_LOGOUT == "auth.logout"
    assert audit.AUTH_LOGIN_FAILED == "auth.login_failed"
    assert audit.AUTH_PASSWORD_CHANGED == "auth.password_changed"
    assert audit.AUTH_SESSION_REVOKED == "auth.session_revoked"
    assert audit.USER_CREATED == "user.created"
    assert audit.USER_UPDATED == "user.updated"
    assert audit.USER_ROLE_CHANGED == "user.role_changed"
    assert audit.USER_PASSWORD_RESET == "user.password_reset"
    assert audit.SETTINGS_UPDATED == "settings.updated"
