#!/usr/bin/env python3
"""Structural lint / coverage gate for the W3-T4 golden-signal dashboards-as-code.

WHY THIS FILE EXISTS (ADR-0046 §4; PRODUCTION.md §11 G-OBS §335)
---------------------------------------------------------------
Visual rendering of a Grafana dashboard needs a live Grafana, which is NOT
available on the build host (named-deferred, L1). The *biting* layer for
dashboards-as-code is therefore: (1) this structural/coverage lint, and (2) the
provisioning ConfigMap passing kubeconform through the chart render. This script
is (1). It is the dashboard equivalent of the W3-T2/T3 `promtool` gate: it fails
the build if the dashboard set drifts from the §335 contract, and it BITES (a
planted bad dashboard fails it — proven by lint_dashboards_bite.sh).

WHAT IT ASSERTS (the §335 coverage gate, ADR-0046 §4 "coverage gate")
---------------------------------------------------------------------
  1. Every *.json under this dir is valid JSON and a well-formed dashboard
     (uid, title, netopsSubject, panels[]).
  2. The NINE §335 subjects are each covered EXACTLY once
     (api, the four queues, postgres, neo4j, redis, llm). A missing or extra
     subject fails (an incomplete dashboard set is incomplete, §335).
  3. Every dashboard carries ALL FOUR golden-signal panels
     (latency, traffic, errors, saturation) — a missing signal fails.
  4. Every panel target `expr` references a KNOWN metric series — a §1 recording
     rule (`slo:`), an ADR-0015 `netops_*` base series, or a documented
     conventional-exporter series declared in EXPORTER_SERIES. An expr that
     references no known series fails — so a RENAMED base metric breaks the
     dashboard lint, not silently the dashboard (ADR-0046 §4).

This is intentionally dependency-free (stdlib `json`/`re` only) so it runs on the
build host (no jsonnet/jq/yamllint present) and in CI without extra installs.

Exit 0 = clean; non-zero = a finding (printed to stderr). Run:
  python deploy/observability/dashboards/lint_dashboards.py
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# The nine §335 subjects (ADR-0046 §4 coverage gate). EXACTLY these, each once.
REQUIRED_SUBJECTS = {
    "api",
    "discovery",
    "config",
    "packet",
    "docs",
    "postgres",
    "neo4j",
    "redis",
    "llm",
}

# The four golden signals — every dashboard must carry all four.
REQUIRED_SIGNALS = {"latency", "traffic", "errors", "saturation"}

# Known in-repo base series (ADR-0015 §2 metrics.py) + the §1 recording-rule
# prefix (slo:). A panel expr must reference at least one known series or a
# documented exporter series. A renamed netops_* metric will NOT match and the
# lint fails (ADR-0046 §4 — break the lint, not the dashboard).
NETOPS_SERIES = {
    "netops_http_requests_total",
    "netops_http_request_duration_seconds_bucket",
    "netops_discovery_runs_total",
    "netops_discovery_duration_seconds_bucket",
    "netops_llm_requests_total",
    "netops_llm_tokens_total",
    "netops_llm_latency_seconds_bucket",
    "netops_agent_first_token_seconds_bucket",
    "netops_change_requests_total",
    "netops_celery_queue_depth",
    "audit_export_lag_seconds",
    "topology_graph_age_seconds",
}
RECORDING_RULE_PREFIX = "slo:"

# Documented conventional-exporter series for the components this chart does NOT
# bundle an exporter for (PG/Neo4j/Redis — expose-don't-bundle, ADR-0015). These
# are the canonical exporter metric names; referencing them is allowed AND the
# dashboard description must FLAG the exporter named-deferral (asserted below).
EXPORTER_SERIES = {
    # postgres_exporter
    "pg_stat_database_blk_read_time_seconds_total",
    "pg_stat_database_xact_commit",
    "pg_stat_database_xact_rollback",
    "pg_stat_database_deadlocks",
    "pg_stat_activity_count",
    "pg_settings_max_connections",
    # neo4j metrics endpoint
    "neo4j_database_transaction_committed_total",
    "neo4j_database_transaction_rollbacks_total",
    "neo4j_dbms_vm_heap_used_ratio",
    # redis_exporter
    "redis_commands_duration_seconds_total",
    "redis_commands_total",
    "redis_commands_processed_total",
    "redis_rejected_connections_total",
    "redis_keyspace_misses_total",
    "redis_memory_used_bytes",
    "redis_memory_max_bytes",
}

# Subjects whose panels are EXPECTED to lean on an exporter series → their
# dashboard description must contain "FLAGGED" (the named-deferral note).
EXPORTER_FLAG_SUBJECTS = {"postgres", "neo4j", "redis"}

ALL_KNOWN_SERIES = NETOPS_SERIES | EXPORTER_SERIES

# A metric token in a PromQL expr: an identifier, optionally `:`-segmented for
# recording rules (slo:netops_api_availability:ratio_rate5m).
_METRIC_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_:]*")
# PromQL function names / keywords that are not metric series (so an expr made
# only of these would NOT count as referencing a series).
_PROMQL_KEYWORDS = {
    "sum", "rate", "irate", "avg", "max", "min", "by", "without", "deriv",
    "histogram_quantile", "increase", "count", "group", "on", "ignoring",
    "and", "or", "unless", "le", "profile", "status", "status_class", "queue",
    "direction", "datname", "Inf", "delta", "predict_linear", "clamp_max",
    "clamp_min", "max_over_time", "min_over_time", "avg_over_time",
}


def _exprs(panel: dict):
    for t in panel.get("targets", []):
        expr = t.get("expr")
        if expr:
            yield expr


def _referenced_series(expr: str) -> set[str]:
    found: set[str] = set()
    for tok in _METRIC_TOKEN.findall(expr):
        if tok.startswith(RECORDING_RULE_PREFIX):
            found.add(tok)  # any slo: series is a recording-rule reference
        elif tok in ALL_KNOWN_SERIES:
            found.add(tok)
    return found


def lint() -> list[str]:
    errors: list[str] = []
    files = sorted(f for f in os.listdir(HERE) if f.endswith(".json"))
    if not files:
        return ["no dashboard JSON files found under deploy/observability/dashboards/"]

    subjects_seen: dict[str, str] = {}
    uids_seen: dict[str, str] = {}

    for fname in files:
        path = os.path.join(HERE, fname)
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{fname}: not valid JSON ({exc})")
            continue

        uid = doc.get("uid")
        title = doc.get("title")
        subject = doc.get("netopsSubject")
        panels = doc.get("panels")

        if not uid:
            errors.append(f"{fname}: missing 'uid'")
        elif uid in uids_seen:
            errors.append(f"{fname}: duplicate uid '{uid}' (also in {uids_seen[uid]})")
        else:
            uids_seen[uid] = fname

        if not title:
            errors.append(f"{fname}: missing 'title'")
        if not isinstance(panels, list) or not panels:
            errors.append(f"{fname}: missing or empty 'panels'")
            panels = []

        if not subject:
            errors.append(f"{fname}: missing 'netopsSubject' (cannot map to a §335 subject)")
        else:
            if subject in subjects_seen:
                errors.append(
                    f"{fname}: subject '{subject}' already covered by {subjects_seen[subject]}"
                )
            subjects_seen[subject] = fname

        # All four golden signals present?
        signals = {p.get("netopsGoldenSignal") for p in panels}
        missing = REQUIRED_SIGNALS - signals
        if missing:
            errors.append(
                f"{fname}: missing golden-signal panel(s): {sorted(missing)} "
                f"(present: {sorted(s for s in signals if s)})"
            )

        # Every panel target references a known series (renamed metric → fail).
        for p in panels:
            ptitle = p.get("title", "<untitled>")
            for expr in _exprs(p):
                refs = _referenced_series(expr)
                if not refs:
                    errors.append(
                        f"{fname}: panel '{ptitle}' expr references no known series "
                        f"(slo:/netops_*/exporter) — renamed metric or typo? expr={expr!r}"
                    )

        # Exporter-backed subjects must FLAG the named-deferral in the description.
        if subject in EXPORTER_FLAG_SUBJECTS:
            desc = (doc.get("description") or "")
            if "FLAGGED" not in desc:
                errors.append(
                    f"{fname}: subject '{subject}' reads conventional-exporter series but "
                    f"the dashboard description does not FLAG the exporter named-deferral "
                    f"(expose-don't-bundle, ADR-0015)."
                )

    # Coverage: exactly the nine §335 subjects.
    covered = set(subjects_seen)
    missing_subjects = REQUIRED_SUBJECTS - covered
    extra_subjects = covered - REQUIRED_SUBJECTS
    if missing_subjects:
        errors.append(f"§335 coverage gap: no dashboard for subject(s) {sorted(missing_subjects)}")
    if extra_subjects:
        errors.append(f"unexpected subject(s) not in the §335 inventory: {sorted(extra_subjects)}")

    return errors


def main() -> int:
    errors = lint()
    if errors:
        print("dashboard lint FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    n = len([f for f in os.listdir(HERE) if f.endswith(".json")])
    print(
        f"dashboard lint PASSED: {n} dashboards, all 9 §335 subjects covered, "
        "all four golden signals per dashboard, every panel target binds to a "
        "known slo:/netops_*/exporter series."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
