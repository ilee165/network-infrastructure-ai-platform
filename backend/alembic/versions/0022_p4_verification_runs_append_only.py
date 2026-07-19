"""P4 W3 review fold (PR #166 F3): append-only parity for verification history.

``audit_chain_verification_runs`` (0021) is 7-year compliance evidence the
audit-integrity report explicitly TRUSTS as persisted history, but 0021 shipped
the table with NO append-only protection — unlike ``audit_log`` (0001
``REVOKE UPDATE, DELETE ... FROM PUBLIC``) and ``approvals`` (0009 guard
trigger). A role holding UPDATE/DELETE on application tables could rewrite a
``break`` outcome to ``clean`` (or delete the row) with nothing detecting it.

This revision mirrors BOTH controls onto the history table:

- ``REVOKE UPDATE, DELETE ... FROM PUBLIC`` — closes incidental PUBLIC access
  by default (a REVOKE cannot bind the table owner/superuser, same caveat as
  0001);
- a ``BEFORE UPDATE OR DELETE`` trigger that RAISES (the 0009 ``approvals``
  pattern) — bites even for the owning application role.

The only writer (``app.services.audit.verify_job._persist_history``) INSERTs
exactly one row per run and never updates or deletes, so no legitimate write
path is affected; the tests/pg fixture TRUNCATEs, which row-level triggers do
not fire on. PostgreSQL-only, guarded like 0009 — the SQLite unit-test schema
skips it. (D4: migrations never import models.)

Revision ID: 0022
Revises: 0021
Create Date: 2026-07-18
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


#: PL/pgSQL guard enforcing the append-only invariant on
#: ``audit_chain_verification_runs``: any ``UPDATE`` or ``DELETE`` raises.
#: Verification outcomes are immutable evidence (ADR-0053 §7.4) — only
#: ``INSERT`` is legitimate. PostgreSQL only; SQLite skips it.
_APPEND_ONLY_FUNCTION = """
CREATE FUNCTION enforce_verification_runs_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'audit_chain_verification_runs is append-only: % on run % is not '
        'permitted (immutable verification evidence, ADR-0053 §7.4)',
        TG_OP, OLD.id
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
"""

_APPEND_ONLY_TRIGGER = """
CREATE TRIGGER trg_verification_runs_append_only
    BEFORE UPDATE OR DELETE ON audit_chain_verification_runs
    FOR EACH ROW EXECUTE FUNCTION enforce_verification_runs_append_only();
"""


def _is_postgresql() -> bool:
    """Dialect guard safe in both online and offline (``--sql``) mode."""
    return op.get_context().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_postgresql():
        op.execute("REVOKE UPDATE, DELETE ON audit_chain_verification_runs FROM PUBLIC")
        op.execute(_APPEND_ONLY_FUNCTION)
        op.execute(_APPEND_ONLY_TRIGGER)


def downgrade() -> None:
    if _is_postgresql():
        op.execute(
            "DROP TRIGGER IF EXISTS trg_verification_runs_append_only "
            "ON audit_chain_verification_runs"
        )
        op.execute("DROP FUNCTION IF EXISTS enforce_verification_runs_append_only()")
        # The upgrade-time REVOKE needs no inverse: PUBLIC holds no table
        # privileges by default (0001 precedent).
