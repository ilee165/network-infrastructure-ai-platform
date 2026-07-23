# Scheduled configuration backup completeness

Alert source: `NetopsConfigBackupCompletenessBurn`. Confirm the reconciliation
query is healthy, then inspect `config_backup_runs` for today's UTC slot. A
disabled schedule is intentionally excluded. For a due slot without terminal
`succeeded` or `empty`, inspect the config worker and queue, restore service,
and redeliver the deterministic nightly slot; repeat delivery is idempotent.

Escalate if the miss is not cleared within 15 minutes. Do not mark the metric
healthy manually or delete the run row.
