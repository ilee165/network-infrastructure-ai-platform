"""FastMCP wiring: six tools registered; calls round-trip through the vault."""

import pytest

from obsidian_mcp.server import create_server
from obsidian_mcp.vault import Vault

EXPECTED_TOOLS = {
    "search_notes",
    "read_note",
    "list_notes",
    "get_template",
    "create_note",
    "append_note",
}


@pytest.fixture()
def server(vault: Vault):
    return create_server(vault)


async def test_six_tools_registered(server) -> None:
    tools = await server.list_tools()
    assert {t.name for t in tools} == EXPECTED_TOOLS


async def test_read_note_roundtrip(server) -> None:
    result = await server.call_tool("read_note", {"path": "04-Knowledge/BGP.md"})
    assert "path-vector" in str(result)


async def test_search_notes_roundtrip(server) -> None:
    result = await server.call_tool("search_notes", {"query": "flapping"})
    assert "BGP.md" in str(result)


async def test_create_then_append_roundtrip(server, vault: Vault) -> None:
    await server.call_tool(
        "create_note",
        {"kind": "inbox", "title": "Hub Test", "content": "## Log\n\n- first\n"},
    )
    await server.call_tool(
        "append_note",
        {"path": "00-Inbox/Hub Test.md", "section": "Log", "content": "- second"},
    )
    note = vault.read_note("00-Inbox/Hub Test.md")
    assert "- first" in note.body and "- second" in note.body


async def test_get_template_lists_required_sections(server) -> None:
    result = await server.call_tool("get_template", {"kind": "incident"})
    text = str(result)
    assert "Root Cause" in text and "Prevention Actions" in text


async def test_error_surfaces_message(server) -> None:
    with pytest.raises(Exception, match="Unknown kind"):
        await server.call_tool("create_note", {"kind": "diary", "title": "x", "content": "y"})


async def test_list_notes_tolerates_non_utf8(server, vault: Vault) -> None:
    (vault.root / "00-Inbox" / "bad-encoding.md").write_bytes(b"\xff\xfe junk")
    result = await server.call_tool("list_notes", {})
    assert "BGP" in str(result)
