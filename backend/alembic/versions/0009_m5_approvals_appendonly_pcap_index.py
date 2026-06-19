"""M5 follow-up: approvals append-only DB guard + pcap retention index.

CodeRabbit review of the M5 PR (#25) surfaced two schema-hardening gaps that
migration 0007 left open:

- ``approvals`` is documented as an *append-only* decision history (0007
  docstring; ADR-0020 §2), but nothing at the DB layer prevented an ``UPDATE`` or
  ``DELETE`` — only the four-eyes constraint trigger (INSERT/UPDATE) existed. This
  adds a PostgreSQL ``BEFORE UPDATE OR DELETE`` guard trigger that RAISES, so the
  append-only audit guarantee is enforced by the database rather than by
  convention. Nothing in the application ever updates or deletes an approval row
  (verified: only INSERTs), so this is a defense-in-depth backstop.
- ``pcap_metadata.retention_expires_at`` is the column the retention/purge job
  scans (``WHERE retention_expires_at < now()``) but had no index — purges would
  degrade to full table scans as captures accumulate. This adds it, matching the
  ``device_id`` / ``requester_id`` / ``tombstoned_at`` indexes 0007 already
  created on the table.

The PostgreSQL-only trigger is guarded by ``_is_postgresql()`` so the SQLite
unit-test schema skips it, exactly like 0007's four-eyes trigger; the index is
portable and created on every dialect. (D4: migrations never import models.)

Revision ID: 0009
Revises: 0008
Create Date: 2026-06-19
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


#: PL/pgSQL guard enforcing the append-only invariant on ``approvals``: any
#: ``UPDATE`` or ``DELETE`` raises. Approvals are an immutable audit record
#: (ADR-0020 §2) — only ``INSERT`` is legitimate. PostgreSQL only; SQLite skips it.
_APPEND_ONLY_FUNCTION = """
CREATE FUNCTION enforce_approvals_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'approvals is append-only: % on approval % is not permitted '
        '(immutable audit history, ADR-0020 §2)', TG_OP, OLD.id
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
"""

_APPEND_ONLY_TRIGGER = """
CREATE TRIGGER trg_approvals_append_only
    BEFORE UPDATE OR DELETE ON approvals
    FOR EACH ROW EXECUTE FUNCTION enforce_approvals_append_only();
"""


def _is_postgresql() -> bool:
    """Dialect guard safe in both online and offline (``--sql``) mode."""
    return op.get_context().dialect.name == "postgresql"


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------


def upgrade() -> None:
    op.create_index(
        op.f("ix_pcap_metadata_retention_expires_at"),
        "pcap_metadata",
        ["retention_expires_at"],
    )
    if _is_postgresql():
        op.execute(_APPEND_ONLY_FUNCTION)
        op.execute(_APPEND_ONLY_TRIGGER)


# ---------------------------------------------------------------------------
# downgrade
# ---------------------------------------------------------------------------


def downgrade() -> None:
    if _is_postgresql():
        op.execute("DROP TRIGGER IF EXISTS trg_approvals_append_only ON approvals")
        op.execute("DROP FUNCTION IF EXISTS enforce_approvals_append_only()")
    op.drop_index(op.f("ix_pcap_metadata_retention_expires_at"), table_name="pcap_metadata")
