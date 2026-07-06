"""P4-W1-T1 (ADR-0050 §7.3): config_archives table — secret-bearing UCS archives.

An **expand-only** migration adding the ``config_archives`` table that stores F5
BIG-IP UCS backups (and any future archive-shaped backup). Each row holds
**double-encrypted** bytes: the archive arrives already passphrase-encrypted
on-box (the per-backup passphrase lives in ``device_credentials``, referenced by
``passphrase_ref``) and is envelope-encrypted a SECOND time at rest with the
D11/ADR-0032 machinery — the same envelope columns as ``device_credentials``
(``ciphertext`` / ``nonce`` / ``wrapped_dek`` / ``dek_nonce`` / ``kek_version``),
with the AAD bound to the archive row id. Reading the DB alone yields
double-encrypted bytes; the vault passphrase row AND the KEK are both required to
reconstruct a usable UCS.

Metadata columns (device, format, size, sha256) are log-safe; there is NO
download endpoint in P4 (metadata-only API surface, ADR-0050 §7.3). The archive
row and its vault passphrase row are an atomic pair.

Portable DDL: ``LargeBinary`` maps to ``bytea`` on PostgreSQL / ``BLOB`` on
SQLite; ``BigInteger`` for ``size_bytes``. No PostgreSQL-specific types.
(D4: migrations never import models.)

Revision ID: 0016
Revises: 0015
Create Date: 2026-07-06
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "config_archives",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("device_id", sa.Uuid(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("archive_format", sa.String(length=16), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("passphrase_ref", sa.String(length=255), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("dek_nonce", sa.LargeBinary(), nullable=False),
        sa.Column("kek_version", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_config_archives"),
        sa.ForeignKeyConstraint(["device_id"], ["devices.id"], name="fk_config_archives_device_id"),
    )
    op.create_index("ix_config_archives_device_id", "config_archives", ["device_id"])
    op.create_index("ix_config_archives_sha256", "config_archives", ["sha256"])


def downgrade() -> None:
    op.drop_index("ix_config_archives_sha256", table_name="config_archives")
    op.drop_index("ix_config_archives_device_id", table_name="config_archives")
    op.drop_table("config_archives")
