# Supervisor Routing Disambiguation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Master Architect supervisor reliably route fault/diagnosis questions to the `troubleshooting` specialist (instead of `discovery`) on weak local models, by sharpening the competing specialist descriptions and the routing prompt, validated by a manual real-LLM routing eval.

**Architecture:** Routing is LLM structured-output (`llm.with_structured_output(RoutingDecision)`) over a roster of `"- {name}: {description}"` lines plus a versioned routing system prompt. The disambiguation surface is therefore (a) each specialist's `description` property and (b) the routing prompt text. We sharpen both. The prompt registry is immutable per `(prompt_id, version)`, so the prompt change is a **new version 3**, not an edit. Deterministic unit tests replay a fixed `RoutingDecision` and so cannot validate routing quality — real validation is a new opt-in, CI-skipped real-LLM eval mirroring `test_provider_parity.py`.

**Tech Stack:** Python 3.12, LangGraph, LangChain, pydantic v2, pytest/pytest-asyncio, Ollama (local LLM), ruff/mypy/import-linter gates.

---

## Background / root cause (read first)

Observed in live testing (2026-06-14): with the local model `qwen3:8b`, the query *"Why can't guest users on 10.0.99.0/24 reach the internet? Read the routing table on the edge firewall edge-fw-01"* routed to the **discovery** specialist, whose tools (`list_devices`, `get_device`, `query_neighbors`) do **not** include `get_device_routes`. The troubleshooting specialist owns `get_device_routes`, so the diagnosis never happened. The supervisor itself worked end-to-end (plan → route → specialist → synthesize → trace); only the routing *choice* was wrong.

Why: the two descriptions overlap for a weak model.
- `discovery` (`backend/app/agents/discovery/agent.py:48-53`): *"Handles discovery, inventory inspection, and neighbor queries. Route here when the user wants to … **list or inspect managed devices** …"* — "inspect managed devices" is broad enough to capture "read/inspect the firewall's routing table."
- `troubleshooting` (`backend/app/agents/troubleshooting/agent.py:188-195`): *"Diagnoses … routing analysis, BGP … Route here when the user reports a symptom … a missing route … and **wants to know why**."* — correct, but the weak model anchored on "read the routing table" and chose discovery.

The fix makes the boundary explicit in both descriptions and adds decision rules + few-shot examples to the routing prompt (a new version).

**Key constraint — deterministic tests cannot prove routing quality.** `backend/tests/agents/framework/test_supervisor.py` and the M3 eval suite (`backend/tests/agents/eval/test_m3_exit_criteria.py`) drive routing with a `ScriptedChatModel` that replays a fixed `RoutingDecision` tool call (see `_routing_reply` in `test_supervisor.py:39-56`). They ignore the prompt and descriptions, so they will keep passing unchanged — but they do NOT validate the fix. Real validation is Task 4 (a real-LLM eval, opt-in, skipped in CI, exactly like `backend/tests/agents/eval/test_provider_parity.py`).

**Immutability note for Task 3:** `register_prompt` raises `ConflictError` if a `(prompt_id, version)` already exists (`backend/app/llm/prompts/__init__.py:46-60`). Version 3 has never been published, so during development you may freely edit the v3 *string literal* and re-run — it only becomes frozen once merged and referenced by recorded traces. Do NOT edit v1 or v2.

---

## File structure

| File | Change | Responsibility |
|------|--------|----------------|
| `backend/app/agents/discovery/agent.py` | Modify `description` | Add explicit boundary: discovery = enumeration, NOT fault diagnosis |
| `backend/app/agents/troubleshooting/agent.py` | Modify `description` | State that reading routing/BGP/OSPF/ACL state to diagnose is troubleshooting |
| `backend/app/llm/prompts/__init__.py` | Add `SUPERVISOR_ROUTING_PROMPT_V3` (version 3) | Routing prompt with decision rules + few-shot examples |
| `backend/tests/agents/discovery/` (existing identity test) | Modify | Assert new boundary text + keep existing keywords |
| `backend/tests/agents/troubleshooting/test_troubleshooting_agent.py` | Modify identity test | Assert new routing-state phrasing + keep existing keywords |
| `backend/tests/llm/test_prompts.py` | Modify/add | Assert v3 is latest, contains guidance, v1/v2 intact |
| `backend/tests/agents/eval/test_routing_eval.py` | Create | Opt-in real-LLM routing eval (CI-skipped) |
| `backend/pyproject.toml` | Modify `[tool.pytest.ini_options] markers` | Register the `routing` marker |

**Gates (run from `backend/`, all must pass before each commit):**
```
ruff check .
ruff format --check .      # ruff format .  to fix
mypy
lint-imports
pytest --cov=app --cov-fail-under=80 -q
```
Windows venv: `backend\.venv\Scripts\python.exe -m <tool>`; `lint-imports` via `backend\.venv\Scripts\lint-imports.exe`. Commit message convention: `fix(agents): <summary>`, end body with `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. After committing, run `graphify update . --force`.

---

## Task 1: Sharpen the discovery agent description

**Files:**
- Modify: `backend/app/agents/discovery/agent.py` (the `description` property, ~lines 47-53)
- Test: the discovery identity test under `backend/tests/agents/discovery/` (find it first: `grep -rn "def test.*description\|def description" backend/tests/agents/discovery/`)

- [ ] **Step 1: Find and read the existing discovery identity test**

Run: `grep -rn "description" backend/tests/agents/discovery/`
Note the exact test name + which keywords it currently asserts (so you keep them). It almost certainly asserts the description is non-empty and mentions discovery/inventory/neighbor terms.

- [ ] **Step 2: Write/extend the failing test**

Add to the discovery identity test class (adjust the test file path/class to what Step 1 found):

```python
    def test_description_states_diagnosis_boundary(self) -> None:
        """Discovery must disclaim fault diagnosis so the router does not grab it
        for troubleshooting questions (regression: routed 'read the routing table
        to find why X is broken' to discovery instead of troubleshooting)."""
        desc = _make_agent().description.lower()  # use this file's existing agent factory
        # Still owns enumeration:
        assert "inventory" in desc
        assert "neighbor" in desc
        # Now explicitly NOT diagnosis:
        assert "diagnos" in desc  # "not for diagnosing ..."
        assert "troubleshooting" in desc  # points the router at the right specialist
```

If the discovery test file has no agent factory like `_make_agent`, construct the agent the way the file's other tests do (check Step 1 output for the constructor).

- [ ] **Step 3: Run the test to verify it fails**

Run: `backend\.venv\Scripts\python.exe -m pytest backend/tests/agents/discovery/ -k diagnosis_boundary -q`
Expected: FAIL (`assert "diagnos" in desc` — current text has no such word).

- [ ] **Step 4: Update the description**

In `backend/app/agents/discovery/agent.py`, replace the `description` return with:

```python
        return (
            "Handles discovery, inventory inspection, and neighbor queries. "
            "Route here when the user wants to trigger a network discovery run, "
            "list or inspect the managed-device inventory, or query LLDP/CDP "
            "neighbor relationships. This specialist only ENUMERATES what exists; "
            "it is NOT for diagnosing why something is broken or for reading a "
            "device's routing/BGP/OSPF/ACL state to explain a fault — that is the "
            "troubleshooting specialist's job. All operations are read-only — no "
            "device configuration is modified."
        )
```

- [ ] **Step 5: Run the test (and the whole discovery test module) to verify pass**

Run: `backend\.venv\Scripts\python.exe -m pytest backend/tests/agents/discovery/ -q`
Expected: PASS (new test green; existing identity tests still green — they assert kept keywords).

- [ ] **Step 6: Commit**

```bash
git add backend/app/agents/discovery/agent.py backend/tests/agents/discovery/
git commit -m "fix(agents): scope discovery description to enumeration, not diagnosis"
```

---

## Task 2: Sharpen the troubleshooting agent description

**Files:**
- Modify: `backend/app/agents/troubleshooting/agent.py` (`description` property, lines ~187-195)
- Test: `backend/tests/agents/troubleshooting/test_troubleshooting_agent.py` (class `TestTroubleshootingIdentity`, `test_description_non_empty_and_on_topic` at ~line 144)

- [ ] **Step 1: Write the failing test**

Add to `class TestTroubleshootingIdentity` in `backend/tests/agents/troubleshooting/test_troubleshooting_agent.py`:

```python
    def test_description_claims_reading_state_to_diagnose(self) -> None:
        """The description must say that READING routing/BGP/OSPF/ACL state to
        diagnose a fault is troubleshooting, so the router does not mistake
        'read the routing table to find why' for discovery/enumeration."""
        desc = _make_agent().description.lower()
        assert "routing table" in desc
        assert "diagnos" in desc
        # Keep the existing on-topic keywords (already asserted elsewhere):
        assert any(w in desc for w in ("bgp", "ospf", "acl", "routing"))
```

- [ ] **Step 2: Run to verify it fails**

Run: `backend\.venv\Scripts\python.exe -m pytest "backend/tests/agents/troubleshooting/test_troubleshooting_agent.py::TestTroubleshootingIdentity::test_description_claims_reading_state_to_diagnose" -q`
Expected: FAIL (`"routing table" in desc` — current text says "routing analysis", not "routing table").

- [ ] **Step 3: Update the description**

In `backend/app/agents/troubleshooting/agent.py`, replace the `description` return with:

```python
        return (
            "Diagnoses network control-plane and data-plane problems: routing "
            "analysis, BGP peer/session analysis, OSPF adjacency analysis, and ACL "
            "analysis. Route here when the user reports a symptom such as a down BGP "
            "peer, a stuck OSPF adjacency, a missing route, or traffic being dropped, "
            "and wants to know why — INCLUDING when answering requires reading a "
            "device's routing table, BGP/OSPF state, or ACLs to diagnose the fault. "
            "Reading a device's state to explain a problem is troubleshooting, not "
            "inventory discovery. All operations are read-only — no device "
            "configuration is modified."
        )
```

- [ ] **Step 4: Run to verify pass**

Run: `backend\.venv\Scripts\python.exe -m pytest backend/tests/agents/troubleshooting/test_troubleshooting_agent.py -q`
Expected: PASS (new test + all existing identity/diagnosis tests green).

- [ ] **Step 5: Commit**

```bash
git add backend/app/agents/troubleshooting/agent.py backend/tests/agents/troubleshooting/test_troubleshooting_agent.py
git commit -m "fix(agents): clarify troubleshooting owns reading device state to diagnose"
```

---

## Task 3: Register routing prompt version 3 (decision rules + examples)

**Files:**
- Modify: `backend/app/llm/prompts/__init__.py` (append after `SUPERVISOR_ROUTING_PROMPT` ~line 153)
- Test: `backend/tests/llm/test_prompts.py`

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/llm/test_prompts.py` (import what it already imports; add `SUPERVISOR_ROUTING_PROMPT_ID`, `get_prompt`, `list_prompts` from `app.llm.prompts` if not present):

```python
class TestRoutingPromptV3:
    def test_v3_is_the_latest_routing_prompt(self) -> None:
        latest = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)
        assert latest.version == 3

    def test_v3_keeps_specialists_placeholder(self) -> None:
        # The supervisor fills {specialists}; losing it would break routing.
        assert "{specialists}" in get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text

    def test_v3_disambiguates_diagnosis_from_enumeration(self) -> None:
        text = get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 3).text.lower()
        assert "troubleshooting" in text
        assert "discovery" in text
        assert "why" in text          # symptom/“wants to know why” rule
        assert "enumerat" in text     # discovery = enumeration rule
        assert "routing table" in text  # the exact phrase that mis-routed

    def test_v1_and_v2_still_registered_immutable(self) -> None:
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 1).version == 1
        assert get_prompt(SUPERVISOR_ROUTING_PROMPT_ID, 2).version == 2
```

- [ ] **Step 2: Run to verify it fails**

Run: `backend\.venv\Scripts\python.exe -m pytest backend/tests/llm/test_prompts.py::TestRoutingPromptV3 -q`
Expected: FAIL (`latest.version == 3` — only v1/v2 exist).

- [ ] **Step 3: Register version 3**

Append to `backend/app/llm/prompts/__init__.py` (after the `SUPERVISOR_ROUTING_PROMPT` (v2) block):

```python
#: Version 3 (routing disambiguation): adds explicit decision rules and few-shot
#: examples so weak local models distinguish fault DIAGNOSIS (troubleshooting —
#: including reading a device's routing/BGP/OSPF/ACL state to explain a fault)
#: from inventory ENUMERATION (discovery). v2 routed "read the firewall's routing
#: table to find why guests can't reach the internet" to discovery, whose tools
#: lack get_device_routes. The {specialists} roster still provides the names.
SUPERVISOR_ROUTING_PROMPT_V3 = register_prompt(
    VersionedPrompt(
        prompt_id=SUPERVISOR_ROUTING_PROMPT_ID,
        version=3,
        text=(
            "You are the Master Architect Agent, the supervisor of a team of "
            "specialist network-operations agents.\n"
            "\n"
            "Read the user's request and decide how to route it. Return a "
            "RoutingDecision with these fields:\n"
            "- specialist: the name of the single best-fit specialist, or null "
            "if no specialist clearly fits.\n"
            "- ambiguous: true when the request is too vague or underspecified "
            "to route confidently (for example 'fix the network'); false when "
            "one specialist clearly fits.\n"
            "- rationale: one short sentence explaining the decision.\n"
            "\n"
            "Available specialists:\n"
            "{specialists}\n"
            "\n"
            "How to choose (match the user's GOAL, not just keywords):\n"
            "- If the user reports a problem or symptom and wants to know WHY "
            "(something is down, unreachable, dropping traffic, or a route / "
            "peer / adjacency is missing or wrong), route to the troubleshooting "
            "specialist. Reading a device's routing table, BGP or OSPF state, or "
            "ACLs IN ORDER TO DIAGNOSE a fault is troubleshooting work, even "
            "though it inspects a device.\n"
            "- If the user only wants to ENUMERATE or LIST what exists (run a "
            "discovery scan, list or inspect the managed-device inventory, or "
            "look up LLDP/CDP neighbors), route to the discovery specialist. "
            "Discovery is inventory enumeration, not fault diagnosis.\n"
            "- If the request is genuinely unclear or could mean several "
            "different things, set ambiguous=true and specialist=null so the "
            "consultant can ask a clarifying question.\n"
            "\n"
            "Examples:\n"
            "- 'Why can't guest users on 10.0.99.0/24 reach the internet? Check "
            "the firewall's routing table.' -> troubleshooting (a fault, asks "
            "why; reading the routing table is to diagnose it).\n"
            "- 'Is BGP peer 10.0.0.2 down on edge-1, and why?' -> "
            "troubleshooting.\n"
            "- 'List all managed devices' or 'what did the last discovery find?' "
            "-> discovery (pure enumeration).\n"
            "- 'Run a discovery scan of 10.0.0.0/24' -> discovery.\n"
            "- 'Fix the network' -> ambiguous=true, specialist=null (too vague).\n"
            "\n"
            "Rules:\n"
            "- Choose the single best fit; never name more than one specialist.\n"
            "- Only use a name from the list above; never invent a specialist.\n"
            "- If the request is ambiguous, or no specialist fits, set "
            "ambiguous=true and specialist=null so the Consultant Agent can "
            "ask a clarifying question — do not guess.\n"
        ),
    )
)
```

- [ ] **Step 4: Run to verify pass**

Run: `backend\.venv\Scripts\python.exe -m pytest backend/tests/llm/test_prompts.py -q`
Expected: PASS. The supervisor already calls `get_prompt(SUPERVISOR_ROUTING_PROMPT_ID)` with no version (`supervisor.py:187`), so it automatically picks v3 (latest) — no supervisor code change needed.

- [ ] **Step 5: Confirm the supervisor unit tests are unaffected**

Run: `backend\.venv\Scripts\python.exe -m pytest backend/tests/agents/framework/test_supervisor.py backend/tests/agents/eval/test_m3_exit_criteria.py -q`
Expected: PASS (scripted model ignores the prompt; deterministic routing unchanged).

- [ ] **Step 6: Commit**

```bash
git add backend/app/llm/prompts/__init__.py backend/tests/llm/test_prompts.py
git commit -m "fix(agents): routing prompt v3 — disambiguate diagnosis vs enumeration"
```

---

## Task 4: Real-LLM routing eval (opt-in, CI-skipped manual gate)

This is the ONLY automated check that validates the fix's effect; it needs a real local model and is skipped in CI, exactly like `backend/tests/agents/eval/test_provider_parity.py` (read that file first — mirror its skip/marker pattern).

**Files:**
- Create: `backend/tests/agents/eval/test_routing_eval.py`
- Modify: `backend/pyproject.toml` — add `routing` to `[tool.pytest.ini_options] markers`

- [ ] **Step 1: Register the `routing` marker**

In `backend/pyproject.toml`, find `[tool.pytest.ini_options]` → `markers = [...]` (it already lists `parity` and `integration`). Add:

```toml
    "routing: real-LLM supervisor routing eval; opt-in, skipped in CI (manual gate).",
```

- [ ] **Step 2: Find the canonical production registry assembly**

Read `backend/app/api/v1/agents.py` function `build_supervisor_for_role` (~lines 113-141): it builds the real `AgentRegistry` (discovery + troubleshooting + consultant) the production supervisor uses. Note exactly how each real agent is constructed (constructor args, any recorders/tools). The eval must build the registry the SAME way so it tests the real descriptions. If a shared helper exists, import it; otherwise replicate its registry construction in the test.

- [ ] **Step 3: Write the eval**

Create `backend/tests/agents/eval/test_routing_eval.py` (adapt the registry construction in `_build_real_registry` to what Step 2 found — the placeholder below assumes default constructors; fix if Step 2 shows otherwise):

```python
"""Real-LLM supervisor routing eval (manual gate).

Validates that the Master Architect routes fault/diagnosis questions to the
troubleshooting specialist and enumeration questions to discovery, using a REAL
local model (not the ScriptedChatModel the deterministic suite uses, which
replays a fixed RoutingDecision and so cannot test routing quality).

Non-deterministic + needs a running Ollama, so — like provider parity and the
M1/M2 live-lab gates — it is opt-in and skipped in CI:

    ollama pull qwen3:8b                     # or any capable local model
    export NETOPS_RUN_ROUTING_EVAL=1
    export NETOPS_LLM_LOCAL_MODEL=qwen3:8b   # model under test
    pytest -m routing backend/tests/agents/eval/test_routing_eval.py -q
"""

from __future__ import annotations

import os

import pytest
from langchain_core.messages import HumanMessage

from app.agents.framework.registry import AgentRegistry
from app.agents.framework.supervisor import build_supervisor_graph, run_supervisor
from app.agents.framework.traces import InMemoryTraceRecorder
from app.core.config import Settings
from app.core.security import Role
from app.llm.providers import get_chat_model

_FLAG = "NETOPS_RUN_ROUTING_EVAL"

pytestmark = pytest.mark.routing

if not os.environ.get(_FLAG):
    pytest.skip(
        f"routing eval is a manual gate; set {_FLAG}=1 (needs a local Ollama) to run it.",
        allow_module_level=True,
    )

# (intent, expected specialist). Each must route correctly for the eval to pass.
_CASES = [
    ("Why can't guest users on 10.0.99.0/24 reach the internet? Read the routing "
     "table on the edge firewall edge-fw-01.", "troubleshooting"),
    ("Is BGP peer 10.0.0.2 down on edge-1, and why?", "troubleshooting"),
    ("The OSPF adjacency to core-sw-01 is stuck in EXSTART — what is wrong?", "troubleshooting"),
    ("List all managed devices in the inventory.", "discovery"),
    ("What devices did the last discovery run find?", "discovery"),
    ("Show me the LLDP neighbors of core-sw-01.", "discovery"),
]


def _build_real_registry() -> AgentRegistry:
    """Build the production specialist registry (real descriptions under test).

    Mirror app/api/v1/agents.py::build_supervisor_for_role. Adjust constructors
    to match that function exactly.
    """
    from app.agents.consultant.agent import ConsultantAgent
    from app.agents.discovery.agent import DiscoveryAgent
    from app.agents.troubleshooting.agent import TroubleshootingAgent

    registry = AgentRegistry()
    registry.register(DiscoveryAgent())
    registry.register(TroubleshootingAgent())
    registry.register(ConsultantAgent())
    return registry


@pytest.mark.parametrize(("intent", "expected"), _CASES)
async def test_routing_picks_expected_specialist(intent: str, expected: str) -> None:
    settings = Settings()  # reads NETOPS_LLM_LOCAL_MODEL / profile from env
    llm = get_chat_model("local", settings)
    graph = build_supervisor_graph(llm, _build_real_registry(), trace_recorder=InMemoryTraceRecorder())
    state = await run_supervisor(graph, [HumanMessage(content=intent)], role=Role.ENGINEER)
    assert state["specialist"] == expected, f"{intent!r} routed to {state['specialist']!r}"
```

- [ ] **Step 4: Verify the eval is skipped by default (CI safety)**

Run: `backend\.venv\Scripts\python.exe -m pytest backend/tests/agents/eval/test_routing_eval.py -q`
Expected: `skipped` (no `NETOPS_RUN_ROUTING_EVAL`), no network touched. Also run `pytest -q` over the suite and confirm no new failures and the `routing` marker raises no "unknown marker" warning.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/agents/eval/test_routing_eval.py backend/pyproject.toml
git commit -m "test(agents): add opt-in real-LLM supervisor routing eval"
```

---

## Task 5: Full gates + live verification + iterate

- [ ] **Step 1: Run all backend gates**

Run (from `backend/`):
```
backend\.venv\Scripts\python.exe -m ruff check .
backend\.venv\Scripts\python.exe -m ruff format --check .
backend\.venv\Scripts\python.exe -m mypy
backend\.venv\Scripts\lint-imports.exe
backend\.venv\Scripts\python.exe -m pytest --cov=app --cov-fail-under=80 -q
```
Expected: all green, exit 0, coverage ≥80%. Fix anything red before proceeding.

- [ ] **Step 2: Live-run the routing eval against a real local model**

Start Ollama on the host with a capable model pulled (the misroute was on `qwen3:8b`, so test that one — and ideally a smaller one like `qwen3.5:2b` to see how far down it holds):
```bash
ollama pull qwen3:8b
# from backend/, with the venv active:
$env:NETOPS_RUN_ROUTING_EVAL=1
$env:NETOPS_LLM_LOCAL_MODEL="qwen3:8b"
$env:NETOPS_OLLAMA_BASE_URL="http://localhost:11434"   # host Ollama
backend\.venv\Scripts\python.exe -m pytest -m routing backend/tests/agents/eval/test_routing_eval.py -q
```
Expected: all 6 cases PASS. The first case is the exact query that previously mis-routed to discovery.

- [ ] **Step 3: If any case still mis-routes — iterate the v3 prompt (NOT a new version yet)**

v3 is unpublished until merge, so edit the `SUPERVISOR_ROUTING_PROMPT_V3` string literal in `backend/app/llm/prompts/__init__.py` directly: strengthen the rule wording or add an example matching the failing case. Re-run Step 2. Do NOT register a v4 — keep iterating v3 until it passes (or until you decide a given tiny model is simply incapable, which you record in the commit message). Re-run `pytest backend/tests/llm/test_prompts.py -q` after edits.

- [ ] **Step 4: Optional full end-to-end via the running stack**

If you want the full HTTP path (matches how it was originally found):
```bash
# bring the stack up, apply migrations, seed the scenario:
docker compose -f deploy/docker/docker-compose.yml --env-file .env up -d --build
docker compose -f deploy/docker/docker-compose.yml exec -T api alembic upgrade head
docker compose -f deploy/docker/docker-compose.yml cp backend/scripts/seed_smb_scenario.py api:/tmp/seed.py
docker compose -f deploy/docker/docker-compose.yml exec -T api python /tmp/seed.py   # prints device ids
```
Set `NETOPS_LLM_LOCAL_MODEL=qwen3:8b` in `.env` first and rebuild api/worker. Login (`admin`/`admin`), `POST /api/v1/auth` is the auth login; agent sessions are `POST /api/v1/agents` with `{"intent": "..."}`. Confirm the firewall-routing intent now produces a trace whose `route` step says `route request to specialist 'troubleshooting'` and the answer cites the missing `10.0.99.0/24` route. **Tear down when done:** `docker compose -f deploy/docker/docker-compose.yml down -v` (wipes the seeded test data) and revert any `.env` test edits.

- [ ] **Step 5: Final commit (only if Step 3 changed the prompt)**

```bash
git add backend/app/llm/prompts/__init__.py
git commit -m "fix(agents): tune routing prompt v3 examples until routing eval passes"
graphify update . --force
```

---

## Self-review checklist (done while writing — recorded for the executor)

- **Spec coverage:** sharpen discovery desc (Task 1) ✓; sharpen troubleshooting desc (Task 2) ✓; prompt with rules+examples as a new version (Task 3) ✓; real validation that can't be faked by scripted tests (Task 4) ✓; live confirm + iterate loop (Task 5) ✓.
- **No supervisor code change needed:** `supervisor.py:187` already fetches the latest prompt version, so registering v3 is sufficient — verify this assumption holds when you read the file.
- **Immutability:** only v3 is added; v1/v2 untouched and asserted intact (Task 3 Step 1).
- **CI stays green & offline:** deterministic supervisor/eval tests unaffected (scripted model); the new routing eval is module-skipped without `NETOPS_RUN_ROUTING_EVAL` (Task 4 Step 4).
- **Open assumption to verify during execution:** the discovery identity test's exact location/name and agent factory (Task 1 Step 1); the real-agent constructors in `build_supervisor_for_role` (Task 4 Step 2). Both have explicit "find first" steps.

---

## Execution context for a fresh session

- Repo: `D:\Multi-Agent workflow\network-infrastructure-ai-platform`, branch `main` (clean as of 2026-06-14; Auth & Account UI merged via PR #15, commit `7d9e162`). **Cut a feature branch first**, e.g. `git checkout -b fix/supervisor-routing-disambiguation`.
- This is a small bugfix, not a milestone — execute inline (subagent-driven optional). It does NOT block M4; it is a recommended pre-M4 cleanup because M4 adds two more specialists (Configuration, Documentation) to the same router, widening the disambiguation surface.
- Graphify is active: run `graphify query "<q>"` before grepping source; `graphify update . --force` after commits.
