# Celery publication ratchet

All production Celery publication crosses
`backend/app/workers/dispatch.py::durable_dispatch`. The boundary validates an
allowlisted task/queue pair, preserves positional or keyword arguments plus
`countdown`, `eta`, and caller-supplied `task_id`, and replaces broker exception
text with the stable `publication_failed` error. The report-outbox path remains
stricter: its payload is identifier-only and its durable dispatch UUID is the
Celery task ID.

## Publication census

The pre-migration census on 2026-07-23 contained these bare production sites:

| Path and symbol | Task | Queue / routing |
|---|---|---|
| `app/api/v1/discovery.py::start_run` | `discovery.run` | `discovery` |
| `app/api/v1/agents.py::launch_capture` (device branch) | `packet.capture_device` | `packet_capture` |
| `app/api/v1/agents.py::launch_capture` (segment branch) | `packet.capture_segment` | `packet_capture` |
| `app/agents/discovery/tools.py::run_discovery` | `discovery.run` | `discovery` |
| `app/workers/tasks/discovery.py::_trigger_topology_sync` | `topology.sync_after_run` | implicit `topology.*` route, now the equivalent explicit `topology` queue |

The post-migration census has no bare application publication sites and no
allowlist exceptions. `app/workers/tasks/report_outbox.py::_relay_core` already
used the wrapper and remains the identifiers-only report publication path.
The wrapper's own `celery_app.send_task` call is the intentional broker
boundary, recognized only at that exact path and symbol.

## Enforcement

`python backend/scripts/check_celery_dispatch.py` parses `backend/app` with the
Python AST and rejects calls whose final attribute is `send_task`,
`apply_async`, or `delay`, including aliased receivers, multiline calls, and
nested attribute paths. Exceptions, if ever approved, must match resolved path,
enclosing symbol, and method kind; the committed exception set is empty.

CI runs the clean-tree check and then the committed syntax fixtures as a
negative control. Locally, the CI-equivalent gate is:

```bash
cd backend
python scripts/check_celery_dispatch.py
! python scripts/check_celery_dispatch.py --negative-control
```
