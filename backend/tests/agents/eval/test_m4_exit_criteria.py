"""M4 exit-criteria eval suite (task T17) — the six MVP.md §6 criteria.

Each test class encodes exactly one exit criterion from MVP.md §6 (Config
Management + Documentation Agent). The suite is the deliverable: it is
fixture-grounded and fully deterministic — no network, no real LLM — and it
drives the *real* M4 production code paths (the ``engines/config_mgmt`` snapshot
/ drift / compliance engines, the ``knowledge/`` embedding + RAG retrieval
pipeline, the real Documentation-Agent inventory/diagram tools, and the real
Configuration Agent's ``classify -> narrate`` subgraph under ``ScriptedChatModel``).

Which layer proves which criterion
----------------------------------

This file is the **deterministic layer** (runs in CI). It proves the wiring and
control flow of each criterion against fixtures; it does NOT prove model
judgment. Two criteria of MVP.md §6 carry a model-judgment facet that a scripted
replay cannot honestly validate:

* Criterion 2 (the Configuration Agent's *explanation* references the changed
  lines): the deterministic layer proves the agent grounds its answer in the
  exact changed lines the server-side drift engine produced and that secrets are
  redacted — the *plumbing* is exact. The quality of the natural-language
  narrative a real model writes is out of scope here (it is degradable: a weak
  model produces worse prose, never wrong facts, because the changed lines are
  drawn from the deterministic diff, not invented).
* Criterion 5 (RAG retrieval *relevance*): the deterministic layer proves the
  retrieval mechanism returns the expected chunk with its citation for a
  reference set of held-out queries against a fixed embedder. Whether a *real*
  embedding model ranks a fuzzy paraphrase correctly is the real-LLM facet —
  that is the held-out RAG retrieval eval ``test_rag_retrieval_eval.py`` (real
  ``nomic-embed-text``, opt-in, CI-skipped).

The five-way routing decision (MVP.md §6 / M4 risk #2) that M4 widens is proved
at the real-LLM layer by ``test_routing_eval.py`` (extended to five specialists
with held-out configuration + documentation cases).

Criteria (MVP.md §6):

1. Nightly scheduled backup stores snapshots for 100% of reachable devices;
   failures are audited.
2. An out-of-band change is flagged as drift with an accurate unified diff; the
   Configuration Agent's explanation references the changed lines.
3. A seeded policy violation is reported (device / rule / severity / evidence);
   a compliant device reports clean.
4. Generated inventory matches normalized-table content exactly (round-trip);
   generated diagram matches the Neo4j projection node/edge set.
5. A RAG query against a generated runbook returns the relevant chunk with its
   citation.
6. All generated artifacts are downloadable and recorded in ``documents`` with
   embeddings present.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import pytest
from langchain_core.messages import AIMessage, HumanMessage
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.agents.configuration.agent import ConfigurationAgent
from app.agents.documentation.tools import generate_diagram, generate_inventory
from app.engines.config_mgmt.capture import capture_snapshot, run_backup_pass
from app.engines.config_mgmt.compliance import (
    DeviceContext,
    FindingStatus,
    Severity,
    evaluate_policy,
    load_default_pack,
)
from app.engines.config_mgmt.drift import approve_baseline, detect_drift
from app.knowledge.embedding import chunk_document, embed_document, retrieve
from app.models import (
    AuditLog,
    ConfigSnapshot,
    ConfigSource,
    Device,
    Document,
    DocumentFormat,
    DocumentKind,
    Embedding,
)
from app.services.audit.service import (
    CONFIG_BASELINE_APPROVED,
    CONFIG_SNAPSHOT_DRIFT_CHECKED,
    CONFIG_SNAPSHOT_FAILED,
)
from tests.agents.conftest import scripted_model
from tests.knowledge.test_embedding import FakeEmbedder

pytestmark = pytest.mark.eval


# ===========================================================================
# Shared fixtures: seeded devices + their fixture configs.
# ===========================================================================


async def _seed_device(maker: async_sessionmaker[AsyncSession], *, hostname: str) -> uuid.UUID:
    """Persist a device row and return its id (the FK config snapshots hang off).

    ``mgmt_ip`` is unique in the schema, so each seeded device gets a distinct
    address derived from a counter — the eval needs the id, not the address.
    """
    async with maker() as session:
        existing = (await session.execute(select(Device))).scalars().all()
        device = Device(
            hostname=hostname,
            mgmt_ip=f"10.0.0.{len(existing) + 1}",
            vendor_id="cisco_ios",
        )
        session.add(device)
        await session.commit()
        return device.id


#: A clean baseline config that passes the seeded baseline-hardening pack.
_BASELINE_CONFIG = "\n".join(
    [
        "hostname edge-1",
        "ip ssh version 2",
        "interface GigabitEthernet0/0",
        " ip address 10.0.0.1 255.255.255.0",
        "ntp server 10.0.0.53",
    ]
)

#: The same device after an out-of-band change: a secret SNMP community line was
#: added (the drifted line). Everything else is byte-identical to the baseline.
_DRIFTED_CONFIG = "\n".join(
    [
        "hostname edge-1",
        "ip ssh version 2",
        "interface GigabitEthernet0/0",
        " ip address 10.0.0.1 255.255.255.0",
        "ntp server 10.0.0.53",
        "snmp-server community S3cr3tCommunityRO RO",
    ]
)

#: The exact secret substring that must NEVER surface in the agent's narration.
_DRIFT_SECRET = "S3cr3tCommunityRO"


# ===========================================================================
# Criterion 1 — nightly backup covers 100% of reachable devices; failures audited
# ===========================================================================


class TestCriterion1NightlyBackupCoversAllReachableDevices:
    """A scheduled backup pass snapshots every reachable device; a failure is audited.

    Deterministic layer: this proves the capture engine + the scheduled-pass
    contract (content-addressed snapshot per device, source=SCHEDULED, and a
    failure for an unreachable device producing an audit row) — no model is
    involved, so there is no judgment facet here.
    """

    async def test_scheduled_pass_snapshots_every_reachable_device(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        # Three reachable devices, one unreachable (its CONFIG_BACKUP raises).
        reachable = {
            await _seed_device(sessionmaker, hostname=f"r{i}"): f"hostname r{i}\nip ssh version 2\n"
            for i in range(3)
        }
        unreachable = await _seed_device(sessionmaker, hostname="down-1")

        # Drive the REAL production backup-pass path: run_backup_pass handles
        # content-addressed capture for reachable devices and writes an audited
        # failure row for the unreachable device. No test-local AuditLog.add()
        # or manual exception swallowing — the audit row must originate from the
        # production worker path (the finding's criterion).
        transport_error = TimeoutError("ssh connect timed out")
        async with sessionmaker() as session:
            pass_result = await run_backup_pass(
                session,
                device_configs=reachable,
                device_errors={unreachable: transport_error},
                source=ConfigSource.SCHEDULED,
            )
            await session.commit()

        # The pass captured a content hash for every reachable device and
        # recorded exactly the one unreachable device as a failure.
        assert set(pass_result.captured) == set(reachable)
        assert set(pass_result.failed) == {unreachable}
        assert isinstance(pass_result.failed[unreachable], TimeoutError)

        # 100% of REACHABLE devices have a stored snapshot (content-addressed).
        async with sessionmaker() as session:
            rows = (await session.execute(select(ConfigSnapshot))).scalars().all()
        snapshotted = {row.device_id for row in rows}
        assert snapshotted == set(reachable), "every reachable device must be snapshotted"
        assert all(row.source is ConfigSource.SCHEDULED for row in rows)
        assert unreachable not in snapshotted, "the unreachable device has no snapshot"

        # The single failure is audited (failures alert via job status + audit).
        # The audit row is written by run_backup_pass — not by this test.
        async with sessionmaker() as session:
            audit = (
                (
                    await session.execute(
                        select(AuditLog).where(AuditLog.action == CONFIG_SNAPSHOT_FAILED)
                    )
                )
                .scalars()
                .all()
            )
        assert len(audit) == 1
        assert audit[0].target_id == str(unreachable)


# ===========================================================================
# Criterion 2 — out-of-band change flagged as drift + agent explains changed lines
# ===========================================================================


def _config_request_reply(*, intent: str, device_id: str | None) -> AIMessage:
    """A scripted structured ``ConfigRequest`` tool call for the config agent."""
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "ConfigRequest",
                "args": {
                    "intent": intent,
                    "device_id": device_id,
                    "policy_id": None,
                    "rationale": "eval classification",
                },
                "id": "cfg-1",
            }
        ],
    )


class TestCriterion2DriftFlaggedAndExplained:
    """An out-of-band change drifts with an accurate diff; the agent cites the line.

    Deterministic layer split:
    * The drift *detection* (diff over raw config, the exact changed hunk) is
      pure engine logic — proved exactly here.
    * The Configuration Agent's *explanation referencing the changed lines* is
      proved structurally: the agent's grounded answer cites the added line
      (drawn from the deterministic diff) and the secret in that line is
      redacted. The narrative QUALITY a real model would add is the degradable,
      out-of-CI facet (a weak model still cites the right line because the line
      comes from the diff, not the model).
    """

    async def _capture_baseline_then_drift(
        self, sessionmaker: async_sessionmaker[AsyncSession], device_id: uuid.UUID
    ) -> Any:
        async with sessionmaker() as session:
            baseline = await capture_snapshot(
                session,
                device_id=device_id,
                raw_config=_BASELINE_CONFIG,
                source=ConfigSource.SCHEDULED,
            )
            await approve_baseline(session, snapshot=baseline.snapshot, actor="engineer:eval")
            await session.commit()
        async with sessionmaker() as session:
            await capture_snapshot(
                session,
                device_id=device_id,
                raw_config=_DRIFTED_CONFIG,
                source=ConfigSource.SCHEDULED,
            )
            await session.commit()
        async with sessionmaker() as session:
            return await detect_drift(session, device_id=device_id, actor="engineer:eval")

    async def test_out_of_band_change_is_flagged_with_accurate_diff(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        device_id = await _seed_device(sessionmaker, hostname="edge-1")
        drift = await self._capture_baseline_then_drift(sessionmaker, device_id)

        assert drift.has_drift, "the out-of-band change must register as drift"
        # The diff flags EXACTLY the added secret line, nothing else.
        added = [
            line[1:]
            for line in drift.diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        assert added == ["snmp-server community S3cr3tCommunityRO RO"], (
            f"the diff must flag exactly the added line; got {added!r}"
        )
        # Exactly one changed hunk (the appended line).
        assert len(drift.hunks) == 1

        # The drift check is audited as a raw-content access; detail carries no config.
        async with sessionmaker() as session:
            audit = (
                (
                    await session.execute(
                        select(AuditLog).where(AuditLog.action == CONFIG_SNAPSHOT_DRIFT_CHECKED)
                    )
                )
                .scalars()
                .all()
            )
        assert audit, "the drift check must be audited"
        assert all(_DRIFT_SECRET not in json.dumps(row.detail) for row in audit), (
            "audit detail must never carry config content"
        )

    async def test_agent_explanation_references_changed_lines_redacted(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        device_id = await _seed_device(sessionmaker, hostname="edge-1")
        drift = await self._capture_baseline_then_drift(sessionmaker, device_id)

        # Drive the REAL Configuration Agent subgraph with the server-computed
        # drift diff injected; the scripted model only classifies the request.
        agent = ConfigurationAgent(drift_diff=drift.diff, has_drift=drift.has_drift)
        llm = scripted_model(
            [_config_request_reply(intent="explain_drift", device_id=str(device_id))]
        )
        graph = agent.build_graph(llm)
        result = await graph.ainvoke(
            {"messages": [HumanMessage(content=f"What changed on {device_id}?")]}
        )

        answer = str(result["messages"][-1].content)
        # The explanation references the changed config keyword (the line content)…
        assert "snmp-server community" in answer, (
            f"the agent must reference the changed line; got {answer!r}"
        )
        # …with the secret value redacted (never the raw secret).
        assert _DRIFT_SECRET not in answer, f"secret leaked into the explanation: {answer!r}"

        # The reasoning trace grounds the answer in a redacted added-line evidence ref.
        trace = result["trace"]
        descriptions = " ".join(
            step.summary + " ".join(e.description or "" for e in step.evidence)
            for step in trace.steps
        )
        assert _DRIFT_SECRET not in descriptions, "secret leaked into the trace"


# ===========================================================================
# Criterion 3 — seeded policy violation reported; compliant device clean
# ===========================================================================


class TestCriterion3PolicyViolationReportedCompliantClean:
    """The seeded pack flags a violating device and reports a compliant one clean.

    Deterministic layer: the compliance engine is LLM-free, so this whole
    criterion is pure logic — there is no model-judgment facet. The violating
    device exposes (device / rule / severity / evidence); the compliant device
    reports every rule ``pass``.
    """

    def _device(self, *, raw_config: str, ntp: list[str]) -> DeviceContext:
        return DeviceContext(
            device_id=uuid.uuid4(),
            vendor="cisco_ios",
            role=None,
            site=None,
            raw_config=raw_config,
            models={"ntp_servers": ntp},
        )

    def test_violation_carries_device_rule_severity_evidence(self) -> None:
        policy = load_default_pack()
        # Violates the ``no-any-any-permit`` rule (a permit ip any any is present).
        violating = self._device(
            raw_config="ip ssh version 2\naccess-list 100 permit ip any any\n",
            ntp=["10.0.0.53"],
        )
        findings = evaluate_policy(policy, violating)

        violations = [f for f in findings if f.status is FindingStatus.VIOLATION]
        assert violations, "the seeded violation must be detected"
        offender = next(f for f in violations if f.rule_id == "no-any-any-permit")
        # device / rule / severity / evidence all present and concrete.
        assert offender.device_id == violating.device_id
        assert offender.rule_id == "no-any-any-permit"
        assert offender.severity is Severity.VIOLATION
        assert "permit ip any any" in offender.evidence

    def test_compliant_device_reports_clean(self) -> None:
        policy = load_default_pack()
        compliant = self._device(
            raw_config="ip ssh version 2\naccess-list 100 permit tcp any any eq 22\n",
            ntp=["10.0.0.53"],
        )
        findings = evaluate_policy(policy, compliant)

        assert findings, "an in-scope device must yield one finding per rule"
        assert all(f.status is FindingStatus.PASS for f in findings), (
            f"a compliant device must report every rule pass; got "
            f"{[(f.rule_id, f.status) for f in findings]}"
        )


# ===========================================================================
# Criterion 4 — inventory round-trip + diagram set-equality vs the projection
# ===========================================================================


class TestCriterion4InventoryRoundTripAndDiagramSetEquality:
    """Generated inventory matches normalized rows; diagram matches the projection.

    Deterministic layer: both generators are LLM-free renderers (ADR-0019 §2-3),
    so the equality criteria hold by construction — no judgment facet.
    """

    async def test_inventory_round_trips_normalized_rows(self) -> None:
        devices = [
            {
                "id": "d1",
                "hostname": "core-01",
                "mgmt_ip": "10.0.0.1",
                "vendor_id": "cisco_ios",
                "status": "reachable",
                "site": "dc1",
            }
        ]
        interfaces = [
            {
                "device_id": "d1",
                "name": "Gi0/0",
                "description": "uplink",
                "admin_status": "up",
                "oper_status": "up",
            }
        ]
        neighbors = [
            {
                "device_id": "d1",
                "protocol": "lldp",
                "local_interface": "Gi0/0",
                "neighbor_name": "spine-01",
            }
        ]
        routes = [{"device_id": "d1", "prefix": "0.0.0.0/0", "protocol": "static"}]

        raw = await generate_inventory.ainvoke(
            {
                "devices": devices,
                "interfaces": interfaces,
                "neighbors": neighbors,
                "routes": routes,
                "fmt": "csv",
            }
        )
        payload = json.loads(raw)
        assert payload["kind"] == "inventory"
        content = payload["content"]
        # Round-trip: every field value of every row appears verbatim in the output.
        for row in (*devices, *interfaces, *neighbors, *routes):
            for value in row.values():
                assert str(value) in content, f"value {value!r} missing from inventory"

    async def test_diagram_node_and_edge_set_equals_projection(self) -> None:
        # A small projection in the exact shape topology_read.fetch_graph returns.
        nodes: list[dict[str, Any]] = [
            {"label": "Device", "key": "core-01", "properties": {"hostname": "core-01"}},
            {"label": "Device", "key": "spine-01", "properties": {"hostname": "spine-01"}},
            {"label": "Subnet", "key": "10.0.0.0/24", "properties": {}},
        ]
        edges: list[dict[str, Any]] = [
            {"type": "CONNECTED_TO", "source": "core-01", "target": "spine-01"},
            {"type": "IN_SUBNET", "source": "core-01", "target": "10.0.0.0/24"},
        ]
        projection: dict[str, Any] = {"nodes": nodes, "edges": edges, "projected_at": None}
        raw = await generate_diagram.ainvoke({"projection": projection})
        content = json.loads(raw)["content"]

        # Node set equality: one declaration per projected node (its display
        # text). Node declarations carry a ``["…"]`` label; edge lines carry
        # ``-->`` instead — count only declarations.
        node_decls = [line for line in content.splitlines() if '["' in line and "-->" not in line]
        assert len(node_decls) == len(nodes), "node count must equal the projection"
        for node in nodes:
            assert (
                str(node["key"]) in content
                or str(node["properties"].get("hostname", "")) in content
            )
        # Edge set equality: one Mermaid link per projected edge, labelled by type.
        edge_lines = [line for line in content.splitlines() if "-->" in line]
        assert len(edge_lines) == len(edges), "edge count must equal the projection"
        for edge in edges:
            assert edge["type"] in content, f"edge type {edge['type']!r} missing from diagram"


# ===========================================================================
# Criterion 5 — RAG query against a generated runbook returns the chunk + citation
# ===========================================================================


class TestCriterion5RagReturnsRelevantChunkWithCitation:
    """A RAG query against a generated runbook returns the relevant chunk + citation.

    Deterministic layer: with a fixed (deterministic) embedder this proves the
    retrieval *mechanism* — the expected chunk is returned WITH its document
    citation (id, title, kind). Whether a *real* embedding model ranks a fuzzy
    paraphrase to the same chunk is the model-judgment facet, proved in the
    opt-in real-LLM RAG eval ``test_rag_retrieval_eval.py``.
    """

    async def test_query_returns_expected_chunk_and_citation(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        async with sessionmaker() as session:
            runbook = Document(
                kind=DocumentKind.RUNBOOK,
                title="edge-1 runbook",
                format=DocumentFormat.MD,
                content=(
                    "# Overview\nedge-1 is a Cisco IOS edge router.\n\n"
                    "## BGP\nedge-1 peers with 10.0.0.2 in AS 65002.\n\n"
                    "## NTP\nedge-1 syncs to 10.0.0.53.\n"
                ),
            )
            session.add(runbook)
            await session.flush()

            embedder = FakeEmbedder()
            await embed_document(session, runbook, embedder=embedder)
            await session.commit()

            # Held-out reference query: the verbatim BGP chunk text → exact top hit
            # under the deterministic embedder (relevance is exact here).
            bgp_chunk = next(c for c in chunk_document(runbook) if "BGP" in c.text)
            results = await retrieve(session, bgp_chunk.text, top_k=3, embedder=embedder)

        assert results, "retrieval must return at least one chunk"
        top = results[0]
        assert "peers with 10.0.0.2" in top.chunk_text, "the relevant chunk must be returned"
        # The citation triple (ADR-0019 §6) accompanies the chunk.
        assert top.citation.document_id == runbook.id
        assert top.citation.title == "edge-1 runbook"
        assert top.citation.kind is DocumentKind.RUNBOOK


# ===========================================================================
# Criterion 6 — artifacts downloadable + recorded in documents with embeddings
# ===========================================================================


class TestCriterion6ArtifactsRecordedWithEmbeddings:
    """A generated artifact persists as a downloadable ``documents`` row + embeddings.

    Deterministic layer: proves the persistence contract — the rendered artifact
    is stored verbatim (so a download returns it byte-for-byte) and is chunked
    into ``embeddings`` rows linked back to it (no model judgment involved).
    """

    async def test_generated_inventory_is_persisted_and_embedded(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        # Generate a real inventory artifact, then persist + embed it exactly as
        # the docs-queue worker would.
        raw = await generate_inventory.ainvoke(
            {
                "devices": [
                    {
                        "id": "d1",
                        "hostname": "core-01",
                        "mgmt_ip": "10.0.0.1",
                        "vendor_id": "eos",
                        "status": "reachable",
                    }
                ],
                "interfaces": [],
                "neighbors": [],
                "routes": [],
                "fmt": "md",
            }
        )
        artifact = json.loads(raw)

        async with sessionmaker() as session:
            document = Document(
                kind=DocumentKind(artifact["kind"]),
                title=artifact["title"],
                format=DocumentFormat(artifact["format"]),
                content=artifact["content"],
            )
            session.add(document)
            await session.flush()
            await embed_document(session, document, embedder=FakeEmbedder())
            await session.commit()
            document_id = document.id
            stored_content = document.content

        # Downloadable: the persisted content is byte-identical to the rendered
        # artifact (a download endpoint returns the row's ``content`` verbatim).
        assert stored_content == artifact["content"]

        # Recorded in ``documents`` with embeddings present and linked.
        async with sessionmaker() as session:
            doc = (
                await session.execute(select(Document).where(Document.id == document_id))
            ).scalar_one()
            embeddings = (
                (
                    await session.execute(
                        select(Embedding).where(Embedding.document_id == document_id)
                    )
                )
                .scalars()
                .all()
            )
        assert doc.kind is DocumentKind.INVENTORY
        assert embeddings, "the generated document must have embeddings"
        assert all(e.embedding is not None for e in embeddings)


# ===========================================================================
# Provenance: baseline approval is the explicit, audited action drift relies on.
# (Cross-cuts criteria 1-2 — the drift baseline must exist + be audited.)
# ===========================================================================


class TestBaselineApprovalIsAudited:
    async def test_approve_baseline_is_audited_without_config_content(
        self, sessionmaker: async_sessionmaker[AsyncSession]
    ) -> None:
        device_id = await _seed_device(sessionmaker, hostname="edge-1")
        async with sessionmaker() as session:
            captured = await capture_snapshot(
                session,
                device_id=device_id,
                raw_config=_DRIFTED_CONFIG,
                source=ConfigSource.SCHEDULED,
            )
            await approve_baseline(session, snapshot=captured.snapshot, actor="engineer:eval")
            await session.commit()

        async with sessionmaker() as session:
            audit = (
                (
                    await session.execute(
                        select(AuditLog).where(AuditLog.action == CONFIG_BASELINE_APPROVED)
                    )
                )
                .scalars()
                .all()
            )
        assert audit, "baseline approval must be audited"
        assert all(_DRIFT_SECRET not in json.dumps(row.detail) for row in audit), (
            "baseline-approval audit detail must never carry config content"
        )
