"""Real-provider parity run for the M3 eval suite (criterion 6, manual gate).

MVP.md §5 exit criterion 6 requires the eval suite to pass on the ``local``
(Ollama) profile *and* at least one external provider profile, proving the D9
multi-LLM portability decision (ADR-0009). Hitting real providers is
non-deterministic, needs a running Ollama daemon / a real Anthropic key, and is
slow — so, exactly like the M1/M2 live-lab exit criteria, it is **deferred to a
manual pre-release gate**: tagged ``parity`` and **skipped in CI by default**.

How to run it (the manual pre-release gate):

    # 1. start a local Ollama with the default model pulled, and/or export a key
    ollama pull llama3.1:8b
    export ANTHROPIC_API_KEY=sk-...           # only for the Anthropic leg
    # 2. opt in explicitly
    export NETOPS_RUN_PROVIDER_PARITY=1
    # 3. run only the parity leg
    pytest -m parity backend/tests/agents/eval/test_provider_parity.py

Without ``NETOPS_RUN_PROVIDER_PARITY`` the whole module is skipped, so the
default unit run (``pytest -q``) and CI never touch the network. The Anthropic
leg additionally skips unless ``ANTHROPIC_API_KEY`` is present.

What it proves: the *same* grounded-answer contract the deterministic suite
asserts under ``ScriptedChatModel`` holds when a real model drives the
supervisor's structured routing and the troubleshooting agent's symptom
classification — i.e. the platform is genuinely provider-portable, not coupled
to the scripted fake. The graph is wired through the production
:func:`~app.llm.providers.get_chat_model` factory, so the mandatory redaction
wrapper is exercised on the real provider too.
"""

from __future__ import annotations

import os

import pytest
from langchain_core.messages import HumanMessage

from app.agents.framework.supervisor import build_supervisor_graph, run_supervisor
from app.agents.framework.traces import InMemoryTraceRecorder
from app.agents.troubleshooting.agent import TroubleshootingAgent
from app.core.config import Settings
from app.core.security import Role
from app.llm.providers import get_chat_model
from tests.agents.eval.conftest import (
    DEVICE_Y,
    PEER_X,
    InMemoryAuditSink,
    bgp_tool_patched,
    build_eval_registry,
    make_fake_bgp_tool,
)

#: Opt-in env flag for the manual pre-release gate. Unset => the module is
#: skipped wholesale, so CI and the default unit run never hit a provider.
_PARITY_FLAG = "NETOPS_RUN_PROVIDER_PARITY"

# Tag every test here ``parity`` and skip the whole module unless the operator
# explicitly opts in. ``allow_module_level=True`` lets a skip fire at import
# collection time so no provider import or network call is attempted in CI.
pytestmark = pytest.mark.parity

if not os.environ.get(_PARITY_FLAG):
    pytest.skip(
        f"provider parity is a manual pre-release gate; set {_PARITY_FLAG}=1 to run it "
        "(needs a local Ollama and/or ANTHROPIC_API_KEY). Deferred in CI, like the "
        "M1/M2 live-lab exit criteria.",
        allow_module_level=True,
    )


async def _run_bgp_eval(profile: str, settings: Settings) -> str:
    """Drive the canonical BGP-down eval end-to-end on a REAL *profile* model.

    The model comes from the production factory (so redaction wraps it); the
    BGP evidence is still the fixture payload, because the parity gate proves
    *LLM portability of the agent control flow*, not live device access (live
    reads are the M5/lab concern).
    """
    model = get_chat_model(profile, settings)
    recorder = InMemoryTraceRecorder()
    troubleshooting = TroubleshootingAgent(trace_recorder=InMemoryTraceRecorder())
    registry = build_eval_registry(troubleshooting)
    graph = build_supervisor_graph(model, registry, trace_recorder=recorder)
    fake_bgp = make_fake_bgp_tool(InMemoryAuditSink())
    with bgp_tool_patched(fake_bgp):
        result = await run_supervisor(
            graph,
            [HumanMessage(content=f"Why is BGP peer {PEER_X} down on device {DEVICE_Y}?")],
            role=Role.ENGINEER,
        )
    # Portability contract: the supervisor's own trace completed (no orphan).
    trace = result["trace"]
    assert trace is not None, f"[{profile}] supervisor produced no trace"
    assert trace.is_complete, f"[{profile}] supervisor trace was left open"
    return str(result["messages"][-1].content)


class TestProviderParity:
    """The eval's grounded-answer contract holds on every real provider profile."""

    async def test_local_ollama_profile_grounds_the_answer(self, settings: Settings) -> None:
        """The ``local`` (Ollama) profile must reach a grounded BGP diagnosis."""
        answer = await _run_bgp_eval("local", settings)
        assert PEER_X in answer, f"local answer must cite the named peer: {answer!r}"
        assert "idle" in answer.lower(), f"local answer must cite the Idle state: {answer!r}"

    async def test_anthropic_profile_grounds_the_answer(self, settings: Settings) -> None:
        """At least one external profile (Anthropic) must reach the same diagnosis."""
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            pytest.skip("ANTHROPIC_API_KEY not set; the Anthropic parity leg is skipped")
        answer = await _run_bgp_eval("anthropic", settings)
        assert PEER_X in answer, f"anthropic answer must cite the named peer: {answer!r}"
        assert "idle" in answer.lower(), f"anthropic answer must cite the Idle state: {answer!r}"
