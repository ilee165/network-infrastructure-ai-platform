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
    # Window of 1 would be only the last ToolMessage — must drop it as orphan.
    out = bound_react_messages(msgs, max_tool_chars=8000, max_turns=1)
    assert out == []
    # Window of 2: [AI(tool_calls), Tool] is a valid pair.
    out2 = bound_react_messages(msgs, max_tool_chars=8000, max_turns=2)
    assert len(out2) == 2
    assert isinstance(out2[0], AIMessage)
    assert isinstance(out2[1], ToolMessage)
    assert out2[1].tool_call_id == "c2"
