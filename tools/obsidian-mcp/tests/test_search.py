"""Search: AND semantics, weighted ranking, folder filter, snippets, exclusions."""

import pytest

from obsidian_mcp.search import search
from obsidian_mcp.vault import Vault, VaultError


class TestSearch:
    def test_and_semantics_requires_all_tokens(self, vault: Vault) -> None:
        # "path-vector" appears only in BGP.md; "link-state" only in OSPF.md
        assert search(vault, "path-vector link-state") == []

    def test_title_hits_outrank_body_hits(self, vault: Vault) -> None:
        # BGP.md has "BGP" in its title; OSPF.md mentions BGP only in the body.
        hits = search(vault, "bgp")
        assert [h.path for h in hits][:2] == ["04-Knowledge/BGP.md", "04-Knowledge/OSPF.md"]
        assert hits[0].score > hits[1].score

    def test_folder_filter(self, vault: Vault) -> None:
        assert search(vault, "bgp", folder="06-Runbooks") == []

    def test_excluded_dirs_never_match(self, vault: Vault) -> None:
        assert search(vault, "hidden") == []
        assert search(vault, "asset") == []

    def test_snippets_contain_match_context_not_whole_file(self, vault: Vault) -> None:
        hits = search(vault, "flapping")
        assert len(hits) == 1
        assert any("MTU" in s for s in hits[0].snippets)
        assert all(len(s) < 400 for s in hits[0].snippets)

    def test_limit(self, vault: Vault) -> None:
        assert len(search(vault, "definition", limit=1)) == 1

    def test_empty_query_raises(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="Empty query"):
            search(vault, "   ")

    def test_title_falls_back_to_filename(self, vault: Vault) -> None:
        (vault.root / "00-Inbox" / "no-heading.md").write_text("plain text", encoding="utf-8")
        hits = search(vault, "plain")
        assert hits[0].title == "no-heading"
