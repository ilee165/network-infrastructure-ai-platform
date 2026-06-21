# W5-T3 — Neo4j Rebuild-Drill Job + Topology-RTO Metric

| | |
|---|---|
| **Wave** | P1 W5 — Backup / DR baseline |
| **Owner** | `wf-infra` (Job/CronJob + scheduling) with a small `wf-implementer` metric hook in `engines/topology` |
| **Review tier** | sonnet spec + strong quality |
| **Depends on** | W4 (chart) — independent of W5-T1 (no Postgres-restore dependency in the drill itself) |
| **ADRs** | ADR-0030 §2, §5.2; ADR-0005 (D5 — rebuildable projection); ADR-0007/0008 (discovery queue) |
| **PRODUCTION.md** | §8 (Neo4j "no backup required"; rebuild drill quarterly), §11 G-REL (topology-RTO) |
| **Status** | Proposed |

## Objective

Neo4j has **no backup** — DR is re-projection from Postgres, not restore of a graph dump
(ADR-0005 D5). Ship the `neo4j-rebuild-drill` Job that drops/recreates the graph, runs the
`engines/topology` full-rebuild over `normalized_*`, and **emits a `topology_rebuild_seconds`
metric** (the topology-RTO, gate G-REL) plus a node/edge count it asserts against the prior
projection. Built P1; the destroy-and-rebuild drill runs quarterly from P2.

## Scope

**In**
- A `neo4j-rebuild-drill` Job (Helm K8s `Job` + suspended quarterly `CronJob`; Compose one-shot)
  that: (1) drops/recreates the graph, (2) invokes the existing `engines/topology` full-rebuild
  path (L2/L3/DNS builders over `normalized_*` — see `backend/app/engines/topology/rebuild.py`),
  (3) emits `topology_rebuild_seconds` and node/edge counts.
- A thin metric hook in `engines/topology` (or the rebuild entrypoint) exporting
  `topology_rebuild_seconds` (Prometheus histogram/gauge, ADR-0015 / D15) + `topology_rebuild_nodes`
  / `_edges` gauges, so the drill produces a gate-checkable number, not a log line.
- Count-assertion: rebuilt node/edge counts match the pre-wipe projection within tolerance.
- **Optional opt-in** `neo4j-admin dump` fast-start (off by default — stays true to D5: the
  projection is disposable; if enabled it is validated against the rebuild, never authoritative).
- Discovery-chain hook: when the DR scenario also lost recent discovery results, the drill can
  chain a `discovery`-queue run before projection (ADR-0030 §2) so the rebuilt graph reflects live
  reality; the headline metric measures the projection path at certified scale.

**Out**
- Postgres restore (W5-T1/T2) — the drill assumes an authoritative Postgres (restored or live).
- Full-platform cross-store drill (W5-T5 §5.3 chains restore→rebuild).
- HA / streaming replication (P2).

## Requirements (grounded in ADR-0030 §2, §5.2; ADR-0005 §3)

1. **Re-project, do not restore a dump** (ADR-0030 §2 / Alt #2). Restoring a stale `neo4j-admin
   dump` after a Postgres restore could reintroduce a projection that disagrees with the
   authoritative store — forbidden by D5. The dump is opt-in fast-start only.
2. **Emit the topology-RTO metric.** `topology_rebuild_seconds` is the G-REL number; the drill's
   pass/fail is `value < topology-RTO` where the PROPOSED target is **< 30 min at 5,000 devices**
   (ADR-0030 §2/§6). Target is PROPOSED — parameterized, flagged for Consultant §12.
3. **Count assertion turns "rebuildable" into a checkable invariant** (ADR-0005's contract):
   node/edge counts match the pre-wipe projection; a mismatch is a drill failure (the projection
   pipeline is incomplete — ADR-0030 Negative).
4. **Job independence** (ADR-0030 §4): plain K8s `CronJob`, not Celery beat.
5. **This is the same job that runs the G-REL "destroy-and-rebuild" line** (ADR-0030 §5.2) — one
   artifact, two uses (drill + gate metric).
6. **Built P1, executed P2** — wire + green dry-run at a small seeded scale in CI; the
   5,000-device certified-scale run is lab-deferred (P1-PLAN.md §6).

## Contracts / artifacts

- `deploy/kubernetes/<chart>/templates/backup/neo4j-rebuild-drill-job.yaml` — `Job` + suspended
  quarterly `CronJob`, behind `backup.drills.neo4j.enabled` (+ `dump.enabled: false` opt-in knob).
- `backend/app/engines/topology/` metric hook — `topology_rebuild_seconds` histogram +
  node/edge gauges exposed on `/metrics` (reuse the D15 metrics registry; mirror the existing
  metric usage in `engines/packet/analysis.py`).
- Drill entrypoint (reuse `engines/topology/rebuild.py` full-rebuild) + count-assertion harness.
- Structured output `DRILL neo4j_rebuild seconds=<n> nodes=<n> edges=<n> result=PASS|FAIL` for the
  W5-T5 evidence collector.

## Test & gate plan

- Unit/integration: rebuild over a seeded `normalized_*` fixture emits the metric and matching
  counts; assert metric is registered on `/metrics`. (Python TDD for the metric hook — ruff/mypy/
  pytest, the one Python slice of this task.)
- Drill dry-run: wipe → rebuild → counts match → `topology_rebuild_seconds` recorded; a deliberately
  truncated `normalized_*` fixture makes the count assertion **fail** (proves it bites).
- Infra gates: `helm lint` / `kubeconform` / `kube-linter` / `conftest` — Job present, runAsNonRoot,
  resource limits, dump opt-in defaults off.

## Exit criteria

- [ ] Rebuild-drill Job re-projects the graph from `normalized_*` and emits
      `topology_rebuild_seconds` + node/edge counts on `/metrics` (G-REL, G-OBS).
- [ ] Count assertion matches pre-wipe projection and fails on an incomplete projection.
- [ ] `neo4j-admin dump` is opt-in, off by default; when on, validated against the rebuild.
- [ ] Pass/fail = `seconds < topology-RTO` (PROPOSED, parameterized).
- [ ] Python metric hook passes ruff/mypy/pytest; infra gates green.

## Workflow (P1-PLAN.md §3)

`wf-infra` (strong) owns the Job/scheduling; the `topology_rebuild_seconds` hook is a small
`wf-implementer` Python slice folded into the same task/commit. → `wf-spec-reviewer` (sonnet) +
`wf-quality-reviewer` (strong) in parallel → `wf-fixer` if findings → `wf-verifier` →
**one atomic commit**.

## Risks

- DR correctness now depends on the rebuild path working **at scale** (ADR-0030 Negative): a slow
  rebuild on a large estate directly threatens the topology-RTO gate. The metric makes that
  visible; the 5,000-device validation is P2/lab-deferred.
- Topology-RTO < 30 min is PROPOSED (§6) — parameterized, re-bases on the Consultant §12 answer.
