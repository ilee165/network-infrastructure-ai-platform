# W3-T6 — SOC 2 CC-series evidence mapping (PROPOSED default): mapping doc + report-metadata regime tags

| | |
|---|---|
| **Wave** | P4 W3 — Compliance & audit reporting suite |
| **Owner** | `wf-implementer-light` |
| **Review tier** | sonnet |
| **Depends on** | W3-T2..T5 (maps the four shipped reports) |
| **ADRs** | ADR-0053 §8 (binding) |
| **PRODUCTION.md** | §7 (regime mapping), §12 (compliance-regimes open item) |
| **Status** | Proposed |

## Objective

Implement the ADR-0053 §8 regime layer: **the authoritative report↔control
mapping doc structuring the four reports as SOC 2 CC-series evidence (the
PROPOSED default until the Consultant's compliance-regimes item is answered) +
the `report_runs.regime_tags` defaults per kind**, versioned so generated
artifacts snapshot the mapping in force.

## Scope

**In** — the mapping doc (`docs/` per CLAUDE.md Development Standards): per
report kind, the CC-series controls it evidences and how (change →
`soc2:CC8.1`; posture → `soc2:CC7.1`/`CC4.1`; access review →
`soc2:CC6.1–CC6.3`; audit integrity → `soc2:CC7.2`), what each control
requires and which artifact fields satisfy it, and the named limits (e.g.
F5/VMware config drift out-of-scope in P4); the default `regime_tags` per kind
wired into generation, snapshotting the mapping version; the doc states
PROPOSED status + the rebase path (an ISO 27001/NIST answer re-tags and
re-maps via a doc revision — content is regime-neutral, artifacts are not
invalidated).

**Out** — any report content/redesign (tags are metadata only); answering the
Consultant item; certification claims of any kind (Q7 default: SOC 2 Type
II-*aligned*, no formal claims).

## Requirements (grounded in ADR-0053 §8)

1. **Tags are metadata only** — report content stays regime-neutral; a regime
   answer re-maps without redesigning reports or invalidating artifacts.
2. **Versioned mapping** — `regime_tags` snapshot the mapping version in force
   at generation.
3. **Honest limits named** — controls only partially evidenced (e.g. posture
   coverage gaps) are stated, not implied covered.
4. **PROPOSED, not decided** — the doc carries the open-item pointer (§12) so
   a future owner answer converts it cleanly.

## Contracts / artifacts

- Mapping doc; per-kind tag defaults in generation config; doc linked from the
  reports API docs.

## Test & gate plan

- Full gate suite (docs + the small tag-default wiring); a test asserting each
  kind's generated run carries its default tags + mapping version.
- Drift guard: a change to the mapping doc without a corresponding
  mapping-version bump fails the check — artifacts cannot be mislabeled by a
  doc-only revision.

## Exit criteria

- [ ] Mapping doc published: four reports ↔ CC-series controls, evidence fields, named limits, PROPOSED status + rebase path.
- [ ] `regime_tags` defaults live per kind, snapshotting the mapping version.
- [ ] One atomic commit.

## Workflow

`wf-implementer-light` drafts → combined sonnet review → fixer if findings → verifier → one atomic commit.

## Risks

- **Over-claiming** — mapping language must evidence, not certify; the Q7
  default is "aligned", never "compliant".
- **Tag/doc drift** — tags snapshot a version; a doc revision without a
  version bump silently mislabels artifacts.
