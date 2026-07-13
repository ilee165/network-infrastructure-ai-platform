"""Wave 5 T7: ReAct prompt bounding (tool truncation + history window)."""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from app.agents.framework.base import _TOOL_TRUNCATION_MARKER, bound_react_messages


def test_tool_message_truncated_at_cap() -> None:
    big = "x" * 500
    msgs = [
        HumanMessage(content="hi"),
        AIMessage(content="call"),
        ToolMessage(content=big, tool_call_id="t1"),
    ]
    out = bound_react_messages(msgs, max_tool_chars=100, max_turns=40)
    tool = next(m for m in out if isinstance(m, ToolMessage))
    assert len(tool.content) <= 100
    assert _TOOL_TRUNCATION_MARKER in tool.content


def test_history_window_keeps_tail() -> None:
    msgs = [HumanMessage(content=f"m{i}") for i in range(10)]
    out = bound_react_messages(msgs, max_tool_chars=8000, max_turns=3)
    assert len(out) == 3
    assert out[0].content == "m7"
    assert out[-1].content == "m9"


def test_history_window_drops_orphaned_leading_tool_messages() -> None:
    """max_turns slice must not leave a ToolMessage without its AIMessage."""
    msgs = [
        HumanMessage(content="q"),
        AIMessage(content="", tool_calls=[{"name": "t", "args": {}, "id": "c1"}]),
        ToolMessage(content="tool-result-1", tool_call_id="c1"),
        AIMessage(content="", tool_calls=[{"name": "t", "args": {}, "id": "c2"}]),
        ToolMessage(content="tool-result-2", tool_call_id="c2"),
    ]
    # Window of 1 is only the last ToolMessage — dropped as orphan; the window
    # would drain to [] so the earliest HumanMessage (user intent) is
    # re-anchored instead of invoking the model with zero messages.
    out = bound_react_messages(msgs, max_tool_chars=8000, max_turns=1)
    assert len(out) == 1
    assert isinstance(out[0], HumanMessage)
    assert out[0].content == "q"
    # Window of 2: [AI(tool_calls), Tool] is a valid pair but assistant-first
    # (Anthropic 400s); the intent is prepended and the pair stays adjacent.
    out2 = bound_react_messages(msgs, max_tool_chars=8000, max_turns=2)
    assert len(out2) == 3
    assert isinstance(out2[0], HumanMessage)
    assert out2[0].content == "q"
    assert isinstance(out2[1], AIMessage)
    assert isinstance(out2[2], ToolMessage)
    assert out2[2].tool_call_id == "c2"


def test_multiple_leading_orphans_dropped_then_intent_prepended() -> None:
    """One AI turn can issue parallel tool calls; a window slicing mid-burst
    starts with several consecutive orphaned ToolMessages."""
    msgs = [
        HumanMessage(content="q"),
        AIMessage(
            content="",
            tool_calls=[
                {"name": "t", "args": {}, "id": "c1"},
                {"name": "t", "args": {}, "id": "c2"},
                {"name": "t", "args": {}, "id": "c3"},
            ],
        ),
        ToolMessage(content="r1", tool_call_id="c1"),
        ToolMessage(content="r2", tool_call_id="c2"),
        ToolMessage(content="r3", tool_call_id="c3"),
        AIMessage(content="done"),
    ]
    # Window of 3 = [Tool(r2), Tool(r3), AI(done)]: both orphans dropped, then
    # assistant-first triggers the intent prepend.
    out = bound_react_messages(msgs, max_tool_chars=8000, max_turns=3)
    assert len(out) == 2
    assert isinstance(out[0], HumanMessage)
    assert out[0].content == "q"
    assert isinstance(out[1], AIMessage)
    assert out[1].content == "done"


def test_assistant_first_window_prepends_intent() -> None:
    msgs = [
        HumanMessage(content="q"),
        AIMessage(content="a1"),
        AIMessage(content="a2"),
    ]
    out = bound_react_messages(msgs, max_tool_chars=8000, max_turns=2)
    assert [type(m) for m in out] == [HumanMessage, AIMessage, AIMessage]
    assert out[0].content == "q"
    assert out[1].content == "a1"


def test_human_first_window_returned_unchanged() -> None:
    """A window already anchored on a HumanMessage gets no duplicate intent."""
    msgs = [
        HumanMessage(content="old-intent"),
        AIMessage(content="a1"),
        HumanMessage(content="follow-up"),
        AIMessage(content="a2"),
    ]
    out = bound_react_messages(msgs, max_tool_chars=8000, max_turns=2)
    assert len(out) == 2
    assert isinstance(out[0], HumanMessage)
    assert out[0].content == "follow-up"


def test_no_human_message_anywhere_returns_orphan_dropped_window() -> None:
    """Degenerate history with no HumanMessage: no intent to re-anchor on, so
    the orphan-dropped window is returned as-is (possibly empty)."""
    msgs = [
        AIMessage(content="", tool_calls=[{"name": "t", "args": {}, "id": "c1"}]),
        ToolMessage(content="r1", tool_call_id="c1"),
    ]
    assert bound_react_messages(msgs, max_tool_chars=8000, max_turns=1) == []
    out = bound_react_messages(msgs, max_tool_chars=8000, max_turns=2)
    assert len(out) == 2
    assert isinstance(out[0], AIMessage)
    assert isinstance(out[1], ToolMessage)
