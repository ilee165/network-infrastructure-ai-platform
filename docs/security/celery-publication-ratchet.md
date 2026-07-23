# Celery publication ratchet

All production Celery publication crosses one of the two exact boundaries in
`backend/app/workers/dispatch.py`. `durable_dispatch` validates an allowlisted
task/queue pair and preserves positional or keyword arguments plus `countdown`,
`eta`, and caller-supplied `task_id`. `durable_dispatch_canvas` accepts only the
two established chord shapes (discovery collection/continuation and config
capture/finalization), validates any explicit signature queue against the
existing prefix route, and publishes without rewriting the header, body,
arguments, options, or implicit routing. Both boundaries replace broker
exception text and its exception graph with the stable `publication_failed`
error. The report-outbox path remains stricter: its payload is identifier-only
and its durable dispatch UUID is the Celery task ID.

## Publication census

The pre-migration census on 2026-07-23 contained these bare production sites:

| Path and symbol | Task | Queue / routing |
|---|---|---|
| `app/api/v1/discovery.py::start_run` | `discovery.run` | `discovery` |
| `app/api/v1/agents.py::launch_capture` (device branch) | `packet.capture_device` | `packet_capture` |
| `app/api/v1/agents.py::launch_capture` (segment branch) | `packet.capture_segment` | `packet_capture` |
| `app/agents/discovery/tools.py::trigger_discovery_run` | `discovery.run` | `discovery` |
| `app/workers/tasks/discovery.py::_trigger_topology_sync` | `topology.sync_after_run` | implicit `topology.*` route, now the equivalent explicit `topology` queue |
| `app/workers/tasks/discovery.py::_enqueue_discovery_wave` | chord: `discovery.collect_device` → `discovery.continue_wave` | implicit `discovery.*` route |
| `app/workers/tasks/config.py::_dispatch_captures` | chord: `config.capture_device` → `config.finalize_backup_wave` | implicit `config.*` route |

The post-migration census has no bare application publication sites and no
allowlist exceptions. `app/workers/tasks/report_outbox.py::_relay_core` already
used the wrapper and remains the identifiers-only report publication path.
The boundaries' own `celery_app.send_task` and canvas `apply_async` calls are
the intentional broker publications, recognized only at their exact path and
symbols.

## Enforcement

`python backend/scripts/check_celery_dispatch.py` parses `backend/app` with the
Python AST and rejects calls whose final attribute is `send_task`,
`apply_async`, or `delay`, including aliased receivers, multiline calls, and
nested attribute paths. It also rejects callable chord/canvas/signature
publication, including imported or assigned aliases and nested/multiline forms,
while allowing construction-only `.s`, `.si`, `signature`, and chord forms.
Exceptions, if ever approved, must match resolved path, enclosing symbol, and
method kind; the committed exception set is empty.

CI runs the clean-tree check and then the committed syntax fixtures as a
negative control. Locally, the CI-equivalent gate is:

```bash
cd backend
python scripts/check_celery_dispatch.py
! python scripts/check_celery_dispatch.py --negative-control
```
