"""Append-only grant attestation for ``audit_log`` (ADR-0053 §7.4, G-SEC).

The ONE query implementation both attestation sites share:

* the daily chain-verification CronJob (:mod:`app.services.audit.verify_job`)
  persists the outcome per run into ``audit_chain_verification_runs`` — the
  historical half (a transient grant mid-period surfaces as a failed day);
* the audit-integrity report builder
  (:mod:`app.engines.reports.audit_integrity`) re-runs it LIVE at generation
  time — never cached (a cached result would let a granted ``UPDATE`` slip a
  period, the named W3-T5 risk).

The check walks the PostgreSQL catalog for the ``audit_log`` parent **and
every partition** (``pg_inherits``): the table is range-partitioned, a
partition does not inherit the parent's ACL, and a direct ``UPDATE`` grant on
a child would bypass a parent-only check. BOTH ACL surfaces are exploded —
table-level (``pg_class.relacl``) and COLUMN-level (``pg_attribute.attacl``):
``GRANT UPDATE (col) ON audit_log`` is stored only in ``attacl`` yet confers a
working UPDATE path, so a relacl-only walk would attest a false ``clean``. Any
``UPDATE``/``DELETE`` ACL entry whose grantee is not the relation OWNER is a
violation (PUBLIC included). The owner's
implicit privileges are deliberately out of scope: a ``REVOKE`` cannot bind
the owner or a superuser (the migration 0001 caveat) — the hash chain
(ADR-0038) is the tamper-evidence backstop for privileged actors, and this
attestation covers the grantable surface.

On a backend with no grant catalog (the SQLite unit harness) the outcome is
the honest ``unavailable`` token — never a silent ``clean``. Real-PG REVOKE
semantics are asserted in ``tests/pg/test_audit_integrity_pg.py`` (the P2
SQLite-hides-PG-semantics lesson class).

Secure by default: the result carries relation/role names and privilege
keywords only — catalog metadata, never secret material.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import GrantCheckOutcome

__all__ = ["AUDIT_GRANT_PRIVILEGES", "GrantCheckResult", "check_audit_log_grants"]

#: The privileges whose presence breaks the append-only posture (ADR-0011).
AUDIT_GRANT_PRIVILEGES: tuple[str, ...] = ("UPDATE", "DELETE")

#: Parent + every partition (pg_inherits): partitions do NOT inherit the
#: parent ACL, so a direct child grant must not hide from the attestation.
#: TWO ACL legs over the same target set — table-level (``pg_class.relacl``)
#: and column-level (``pg_attribute.attacl``, where ``GRANT UPDATE (col)``
#: lives; it NEVER appears in ``relacl``). ``aclexplode`` of a NULL ACL yields
#: no rows — correct: a NULL ACL is the owner-only default, i.e. no explicit
#: grant exists. ``DISTINCT`` collapses multiple granted columns on one
#: relation to a single (relation, grantee, privilege) entry.
_GRANTS_SQL = text(
    """
    WITH targets AS (
        SELECT c.oid, c.relacl, c.relowner
        FROM pg_class c
        WHERE c.oid = 'audit_log'::regclass
        UNION ALL
        SELECT ch.oid, ch.relacl, ch.relowner
        FROM pg_inherits i
        JOIN pg_class ch ON ch.oid = i.inhrelid
        WHERE i.inhparent = 'audit_log'::regclass
    ),
    acl_entries AS (
        SELECT t.oid, t.relowner, a.grantee, a.privilege_type
        FROM targets t
        CROSS JOIN LATERAL aclexplode(t.relacl) AS a
        UNION ALL
        SELECT t.oid, t.relowner, a.grantee, a.privilege_type
        FROM targets t
        JOIN pg_attribute att
          ON att.attrelid = t.oid
         AND att.attnum > 0
         AND NOT att.attisdropped
        CROSS JOIN LATERAL aclexplode(att.attacl) AS a
    )
    SELECT DISTINCT e.oid::regclass::text AS relation,
           COALESCE(r.rolname, 'PUBLIC') AS grantee,
           e.privilege_type AS privilege
    FROM acl_entries e
    LEFT JOIN pg_roles r ON r.oid = e.grantee
    WHERE e.privilege_type IN ('UPDATE', 'DELETE')
      AND e.grantee <> e.relowner
    ORDER BY relation, grantee, privilege
    """
)


@dataclass(frozen=True, slots=True)
class GrantCheckResult:
    """Outcome of one append-only grant attestation (ADR-0053 §7.4).

    ``grants`` is every offending ACL entry as ``(relation, grantee,
    privilege)`` — role/relation names and privilege keywords only.
    """

    outcome: str
    grants: tuple[tuple[str, str, str], ...]


async def check_audit_log_grants(session: AsyncSession) -> GrantCheckResult:
    """Attest that no ``UPDATE``/``DELETE`` grant exists on ``audit_log``.

    Runs LIVE against the PG catalog on every call (never cached). Returns
    :data:`~app.models.audit.GrantCheckOutcome.UNAVAILABLE` on a backend with
    no grant catalog (SQLite) — the honest token, never a silent clean.
    """
    bind = session.bind
    dialect = bind.dialect.name if bind is not None else ""
    if dialect != "postgresql":
        return GrantCheckResult(outcome=GrantCheckOutcome.UNAVAILABLE.value, grants=())
    rows = (await session.execute(_GRANTS_SQL)).all()
    grants = tuple(
        (str(relation), str(grantee), str(privilege)) for relation, grantee, privilege in rows
    )
    outcome = GrantCheckOutcome.VIOLATION if grants else GrantCheckOutcome.CLEAN
    return GrantCheckResult(outcome=outcome.value, grants=grants)
