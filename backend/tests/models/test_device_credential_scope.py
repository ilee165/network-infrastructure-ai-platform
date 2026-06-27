"""DeviceCredential scope model: covers() truth table + migration-column parity (ADR-0040 §2).

Pure unit tests on the ORM objects (no DB) for the structural least-privilege
predicate, plus a parity check that the model's scope/device columns match the
0012 migration's column lists (the migration docstring's "pinned equal by test").
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from app.models.inventory import CredentialKind, Device, DeviceCredential, DeviceStatus

_MIGRATION = (
    Path(__file__).resolve().parents[2]
    / "alembic"
    / "versions"
    / "0012_p2_device_credential_scope.py"
)


def _cred(
    *,
    site: str | None = None,
    role: str | None = None,
    group: str | None = None,
) -> DeviceCredential:
    return DeviceCredential(
        name="c",
        kind=CredentialKind.SSH,
        scope_site=site,
        scope_role=role,
        scope_device_group=group,
    )


def _device(
    *,
    site: str | None = None,
    role: str | None = None,
    group: str | None = None,
) -> Device:
    return Device(
        hostname="d",
        mgmt_ip="10.0.0.1",
        status=DeviceStatus.NEW,
        site=site,
        role=role,
        device_group=group,
    )


def test_unscoped_credential_is_not_scoped_and_covers_anything() -> None:
    cred = _cred()
    assert cred.is_scoped is False
    assert cred.covers(_device()) is True
    assert cred.covers(_device(site="nyc", role="core", group="dc-a")) is True


@pytest.mark.parametrize(
    ("cred_kwargs", "dev_kwargs", "expected"),
    [
        # single-dimension match / mismatch
        ({"site": "nyc"}, {"site": "nyc"}, True),
        ({"site": "nyc"}, {"site": "lon"}, False),
        ({"role": "core"}, {"role": "core"}, True),
        ({"role": "core"}, {"role": "edge"}, False),
        ({"group": "dc-a"}, {"group": "dc-a"}, True),
        ({"group": "dc-a"}, {"group": "dc-b"}, False),
        # a SET dimension never matches an ABSENT device attribute (fail-closed)
        ({"site": "nyc"}, {}, False),
        ({"role": "core"}, {}, False),
        ({"group": "dc-a"}, {}, False),
        # multi-dimension: ALL set dimensions must match
        ({"site": "nyc", "role": "core"}, {"site": "nyc", "role": "core"}, True),
        ({"site": "nyc", "role": "core"}, {"site": "nyc", "role": "edge"}, False),
    ],
)
def test_covers_truth_table(
    cred_kwargs: dict[str, str], dev_kwargs: dict[str, str], expected: bool
) -> None:
    assert _cred(**cred_kwargs).is_scoped is True
    assert _cred(**cred_kwargs).covers(_device(**dev_kwargs)) is expected


def test_migration_columns_match_model() -> None:
    """The 0012 migration's column lists match the model's scope + device attributes."""
    spec = importlib.util.spec_from_file_location("_mig_0012", _MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    cred_cols = set(DeviceCredential.__table__.columns.keys())
    device_cols = set(Device.__table__.columns.keys())
    assert set(module._SCOPE_COLUMNS) <= cred_cols
    assert set(module._SCOPE_COLUMNS) == {
        "scope_site",
        "scope_role",
        "scope_device_group",
    }
    assert set(module._DEVICE_COLUMNS) <= device_cols
    assert set(module._DEVICE_COLUMNS) == {"role", "device_group"}
