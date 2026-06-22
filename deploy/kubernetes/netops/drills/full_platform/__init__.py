"""Full-platform DR drill (P1 W5-T5, ADR-0030 §5.3, §6).

Composes the three per-tier drills (W5-T2 Postgres PITR -> W5-T3 Neo4j rebuild
over the RESTORED Postgres -> W5-T4 pcap spot-restore) into the end-to-end
"DR-from-backups-alone, onto a clean cluster" drill, then AGGREGATES — never
re-implements — the per-tier structured ``DRILL ...`` lines into the G-REL
evidence table.

This package owns ONLY the orchestration + the line collector; the per-tier
assertions stay in ``postgres_pitr`` / ``topology_rebuild`` / ``pcap`` (W5-T1..T4).
"""
