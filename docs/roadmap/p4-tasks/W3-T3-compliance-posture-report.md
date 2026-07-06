# W3-T3 — Compliance posture report: M4 engine roll-up + trend over time (daily sweep populates run history)

| | |
|---|---|
| **Wave** | P4 W3 — Compliance & audit reporting suite |
| **Owner** | `wf-implementer` |
| **Review tier** | sonnet |
| **Depends on** | **W3-T1** (engine + the §7.2 history tables land in its revision) |
| **ADRs** | ADR-0053 §2/§7.2 (binding), ADR-0018 (compliance engine/policy format — unchanged) |
| **PRODUCTION.md** | §7 (compliance posture report), §11 G-SEC |
| **Status** | Proposed |

## Objective

Implement the ADR-0053 §7.2 posture report: **pass/fail by policy, device, and
severity plus trend over time** — backed by the named run-history persistence
(`compliance_runs`/`compliance_run_findings`) populated by the **daily
`reports.compliance_sweep`** beat task this task wires up (the M4 engine only
ever ran on demand; without the sweep there is no time series to trend).

## Scope

**In** — the `reports.compliance_sweep` task: daily evaluation across
devices/policy packs writing `compliance_runs` + `compliance_run_findings`
rows (status/severity ONLY — **no evidence-excerpt column**, secret-free by
construction, ADR-0053 §6 layer 3); the report payload + queries: latest
posture (by policy/device/severity) + trend series over `compliance_runs`;
out-of-scope vendors surfaced honestly (F5/VMware have no text-config surface
in P4 — ADR-0050 §7.6 / ADR-0051 §3: shown as out-of-scope, not passing);
CSV + PDF templates; regime tags (`soc2:CC7.1`/`CC4.1`); weekly cadence
(PROPOSED); `engineer`+ floor.

**Out** — changes to `evaluate_policy()`/policy format (ADR-0018 unchanged);
evidence excerpts in history or artifacts (live drill-down stays on the
existing on-demand engineer+ endpoint); the history-table migration itself
(rides the W3-T1 revision).

## Requirements (grounded in ADR-0053 §2/§7.2)

1. **Secret-free history by construction** — status/severity columns only;
   no excerpt column exists to misuse.
2. **Trend is real** — series over `compliance_runs` with engine/policy-pack
   version stamped per run; a gap in the sweep is visible, not interpolated.
3. **Out-of-scope ≠ passing** — F5/VMware appear as out-of-scope for config
   drift (the honest posture both plugin ADRs name).
4. **Sweep load bounded** — rides the `docs` queue + the nightly-backup
   fan-out pattern (D8 isolation).
5. **All queries under `tests/pg/`** (trend/window aggregation is exactly the
   class SQLite mismodels).

## Contracts / artifacts

- Sweep task + beat entry; payload + trend queries + templates + regime tags;
  golden fixture for W4-T3.

## Test & gate plan

- Full gate suite; `tests/pg/`: trend aggregation across runs, severity
  roll-up, out-of-scope classification, empty history, sweep idempotency per
  day.
- Skipped-day fixture: a day with no engine sweep renders as an explicit gap
  in the trend — never interpolated or smoothed over.
- Redaction sanity: payload passes `enforce_redaction`.
- Golden CSV/PDF structure fixture green.

## Exit criteria

- [ ] Daily sweep populates run history (status/severity only, no excerpts).
- [ ] Report shows pass/fail by policy/device/severity + trend from persisted history; out-of-scope vendors honest.
- [ ] `tests/pg/` coverage on sweep + every report query; golden fixture in place.
- [ ] One atomic commit.

## Workflow

`wf-implementer` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Excerpt creep** — a future "richer drill-down" adding evidence text to
  history would break redaction layer 3 (rejected alternative #7 in the ADR).
- **Sweep cost growth** with devices × rules — bounded by queue isolation;
  monitor via the §9 duration histogram.
