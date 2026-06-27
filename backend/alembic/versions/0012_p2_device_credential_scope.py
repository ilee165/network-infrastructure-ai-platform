"""P2 W4-T2 (ADR-0040): per-credential scope binding on device_credentials.

Binds each device credential to an optional SCOPE (site / role / device-group) so
a compromised credential is blast-radius bounded (ADR-0040 §2, PRODUCTION.md §5).
``device_credentials`` gains three NULLABLE scope columns:

  * ``scope_site``         — the site a credential is authorized for.
  * ``scope_role``         — the device role (e.g. ``core`` / ``edge`` / ``firewall``).
  * ``scope_device_group`` — a free-form device-group label.

``devices`` gains the two NULLABLE attributes the scope is matched against
(``site`` already exists): ``role`` and ``device_group``. The structural
session-open check compares each SET credential dimension to the device's
corresponding attribute, so the device must carry those attributes for the match
to be a real code check rather than advisory documentation.

A NULL dimension means "matches any" — a credential with all three scope columns
NULL is UNSCOPED (covers every device, the pre-W4-T2 behaviour) so the column add
is a backward-compatible expand: existing rows decode as unscoped, nothing is
forced NOT NULL on a non-empty table. The structural session-open check in
:func:`app.services.credentials.service.decrypt` refuses to materialize a
credential whose set dimensions do not cover the target device.

This migration is purely additive (five nullable VARCHAR columns) and is disjoint
from the W6-T3 KEK-rotation envelope columns — it touches NO crypto column.
Portable DDL: ``String`` renders ``VARCHAR`` on both PostgreSQL and SQLite
(the unit-test backend). (D4: migrations never import models.)

Revision ID: 0012
Revises: 0011
Create Date: 2026-06-26
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The scope dimensions added to device_credentials (ADR-0040 §2). Mirrors the
#: model columns on ``app.models.inventory.DeviceCredential``; the two are pinned
#: equal by test. Length matches the existing ``site`` column on ``devices``
#: (VARCHAR(128)) so a site value fits identically in either table.
_SCOPE_COLUMNS = ("scope_site", "scope_role", "scope_device_group")
#: Device attributes the scope is matched against (``site`` already exists).
_DEVICE_COLUMNS = ("role", "device_group")
_SCOPE_LENGTH = 128


def upgrade() -> None:
    # Additive, nullable, no default: a NULL dimension means "matches any", so an
    # existing row decodes as UNSCOPED (covers all) — an expand-safe backward-
    # compatible column add (PRODUCTION.md §10). No backfill, no NOT NULL.
    for column in _SCOPE_COLUMNS:
        op.add_column(
            "device_credentials",
            sa.Column(column, sa.String(length=_SCOPE_LENGTH), nullable=True),
        )
    for column in _DEVICE_COLUMNS:
        op.add_column(
            "devices",
            sa.Column(column, sa.String(length=_SCOPE_LENGTH), nullable=True),
        )


def downgrade() -> None:
    for column in reversed(_DEVICE_COLUMNS):
        op.drop_column("devices", column)
    for column in reversed(_SCOPE_COLUMNS):
        op.drop_column("device_credentials", column)
