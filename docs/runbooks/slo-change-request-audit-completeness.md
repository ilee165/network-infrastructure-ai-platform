# ChangeRequest execution to audit completeness

Alert source: `NetopsChangeRequestAuditCompletenessBurn`. First distinguish a
query-health/freshness failure from a positive inconsistency count. Restore
PostgreSQL access and rerun the read-only job if unhealthy; it fails closed and
does not replace the last count with zero. For a positive count, compare each
terminal `completed` or `rolled_back` ChangeRequest with its required
`change_request.*` lifecycle actions by `target_id`.

Preserve the append-only audit chain. Do not synthesize, update, or delete audit
rows; escalate the missing lifecycle record as an integrity incident.
