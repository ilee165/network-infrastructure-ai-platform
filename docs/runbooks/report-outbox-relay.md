# Report outbox relay recovery

This runbook covers ADR-0059 report dispatch. Transport is at least once; the
stable dispatch ID and atomic report-run claim provide one render and terminal
state-transition effect.

## Signals

- `NetopsReportOutboxBacklog`: pending envelopes are accumulating or the oldest
  pending envelope is over five minutes old.
- `NetopsReportOutboxDead`: a relay envelope exhausted retry or failed envelope
  validation.
- `netops_report_outbox_events_total{event="recovered"}`: stale claims were
  returned to pending after a relay crash.

## Triage and recovery

1. Confirm Celery beat and a docs worker are healthy and that PostgreSQL and the
   broker are reachable.
2. Inspect counts by `dispatch_outbox.state` and the stable `last_error_code`.
   Never copy `payload_json` into tickets or chat.
3. A stale `claimed` row is recovered by `reports.outbox_reaper`; do not update
   leases by hand.
4. Restore broker service and allow pending rows to drain. A crash after broker
   acknowledgement can redeliver the same ID; this is expected and safe.
5. For a `dead` row, resolve the typed code. An admin may call
   `POST /api/v1/reports/outbox/{dispatch_id}/requeue`; the API revalidates the
   allowlisted envelope and writes `report.outbox_requeued` to the audit chain.
   Do not edit the payload or state directly.

Escalate if pending age continues increasing for 15 minutes after broker and
worker health recover, or if dead rows recur.
