# Golden-signal Grafana dashboards-as-code (W3-T4)

Grafana dashboards-as-code for the four **golden signals** (latency, traffic,
errors, saturation) of every §335 subject, per **ADR-0046 §4** and
**PRODUCTION.md §6 / §11 G-OBS §335**. No click-ops: the dashboards are JSON in
this repo, linted in CI, and provisioned via the Helm chart.

## Coverage — the nine §335 subjects (one dashboard each)

| Subject | File | Built on |
|---|---|---|
| api | `netops-api.json` | W3-T2 `slo:netops_api_*` recording rules + `netops_http_*` |
| discovery queue | `netops-queue-discovery.json` | `slo:netops_discovery_success:*` + `netops_discovery_*` + `netops_celery_queue_depth` |
| config queue | `netops-queue-config.json` | `netops_celery_queue_depth{queue="config"}` |
| packet queue | `netops-queue-packet.json` | `netops_celery_queue_depth{queue=~"packet_capture\|packet_analysis"}` |
| docs queue | `netops-queue-docs.json` | `netops_celery_queue_depth{queue="docs"}` |
| Postgres | `netops-postgres.json` | conventional `postgres_exporter` series (FLAGGED) |
| Neo4j | `netops-neo4j.json` | `slo:netops_topology_projection_lag:seconds` + Neo4j metrics endpoint (FLAGGED) |
| Redis | `netops-redis.json` | conventional `redis_exporter` series (FLAGGED) |
| LLM providers | `netops-llm.json` | `netops_llm_*` (ADR-0009/ADR-0015) |

Panels read the **same** W3-T2 §1 recording-rule `slo:` series the W3-T3 burn-rate
alerts read, so the dashboard and the alert never diverge (ADR-0046 §1/§4). A
renamed base metric breaks `lint_dashboards.py`, not silently the dashboard.

## Gates (the biting layer)

Visual rendering is **named-deferred (L1)** — there is no live Grafana on the
build/CI host, so a pixel-level render is not the gate. The biting layer is:

1. `lint_dashboards.py` — structural + coverage lint: all 9 subjects × 4 golden
   signals present; every panel target binds to a known `slo:` / `netops_*` /
   documented-exporter series; exporter-backed subjects FLAG the named-deferral.
2. `run-dashboard-lint-bite.sh` — proves the lint **bites**: a dropped golden
   signal, a renamed metric, and a dropped subject each fail; runs
   `sync-to-chart.sh` and then asserts canonical source == chart-embedded copy
   (no embed drift).
3. `helm template … --set observability.grafanaDashboards.enabled=true` +
   `kubeconform` on the provisioning ConfigMap (run in the CI `observability` job).

Run locally:

```bash
python deploy/observability/dashboards/lint_dashboards.py
bash   deploy/observability/dashboards/run-dashboard-lint-bite.sh
```

Before running `helm lint`/`helm template`/`helm package` against
`deploy/kubernetes/netops` locally, sync the canonical dashboards into the
chart first (CI does this automatically — see below):

```bash
bash deploy/observability/dashboards/sync-to-chart.sh
```

## Provisioning

Enable on a cluster running Grafana with the dashboard sidecar
(kube-prometheus-stack):

```yaml
observability:
  grafanaDashboards:
    enabled: true   # OFF by default — expose-don't-bundle (ADR-0015)
```

This renders `…-grafana-dashboards` ConfigMap labelled `grafana_dashboard: "1"`
(override `sidecarLabel` for a different sidecar) embedding every dashboard JSON.
Helm `.Files.Get` cannot read outside the chart root, so
`sync-to-chart.sh` copies this canonical source into
`deploy/kubernetes/netops/dashboards/` at **build time**, before every
`helm lint`/`helm template`/`helm package` (CI wires this into both the `infra`
and `observability` jobs — see `.github/workflows/ci.yml`). That copy is a
build artifact, not a committed file (`.gitignore`); the bite script re-runs
the sync and asserts the result stays byte-identical to this canonical source.

## FLAGGED — named-deferred (not fabricated)

These are honest gaps where no in-repo Prometheus series exists yet; the dashboard
references the conventional series and flags the deferral rather than inventing a
`netops_*` metric (the recording-rules flagged-gap discipline, ADR-0046 §1):

- **Postgres / Redis** — no in-repo series. Panels read the conventional
  `postgres_exporter` / `redis_exporter` series. Wiring those exporters +
  ServiceMonitors is named-deferred to the operator (expose-don't-bundle).
- **Neo4j** — only the platform's own projection-freshness gauge is native
  (`slo:netops_topology_projection_lag:seconds`, §6 row 7). Traffic / errors /
  heap-saturation read the Neo4j metrics endpoint; enabling it is operator-deferred.
- **Non-discovery worker queues** (config/packet/docs) — no per-queue
  task-failure counter or task-runtime histogram is emitted today; panels use the
  `netops_celery_queue_depth` backlog/derivative as the stall/latency proxy. A
  per-queue `netops_celery_task_failures_total{queue}` + a task-runtime histogram
  are named-deferred to the worker-metrics owner.
- **LLM errors** — `netops_llm_requests_total` has `{profile, model}` only (no
  outcome/status label) and there is no `netops_llm_errors_total`, so a true LLM
  error-rate cannot be plotted; the errors panel uses the latency tail as the
  degradation proxy. Adding an `outcome` label (or an errors counter) is
  named-deferred to the LLM-metrics owner — needed so the W3-T5
  LLM-provider-failure fault-injection can alert on an error ratio, not just latency.
