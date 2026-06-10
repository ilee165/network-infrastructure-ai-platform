"""Vault primitives: construction, path safety, frontmatter, read/write/list."""

from pathlib import Path

import pytest

from obsidian_mcp.vault import Vault, VaultError, split_frontmatter


class TestConstruction:
    def test_rejects_missing_root(self, tmp_path: Path) -> None:
        with pytest.raises(VaultError, match="does not exist"):
            Vault(tmp_path / "nope")

    def test_rejects_root_without_templates_folder(self, tmp_path: Path) -> None:
        with pytest.raises(VaultError, match="10-Templates"):
            Vault(tmp_path)


class TestPathSafety:
    def test_resolves_inside_vault(self, vault: Vault) -> None:
        assert vault.resolve("04-Knowledge/BGP.md").is_file()

    def test_rejects_traversal(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="escapes the vault"):
            vault.resolve("../outside.md")

    def test_rejects_absolute_path(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="escapes the vault"):
            vault.resolve("C:/Windows/win.ini")


class TestFrontmatter:
    def test_parses_frontmatter_and_body(self) -> None:
        fm, body = split_frontmatter("---\ntags: [a]\n---\n# Hi\n")
        assert fm == {"tags": ["a"]}
        assert body == "# Hi\n"

    def test_no_frontmatter_returns_empty_mapping(self) -> None:
        fm, body = split_frontmatter("# Hi\n")
        assert fm == {}
        assert body == "# Hi\n"

    def test_unclosed_frontmatter_is_treated_as_body(self) -> None:
        fm, body = split_frontmatter("---\ntags: [a]\n# Hi\n")
        assert fm == {}
        assert body.startswith("---")


class TestReadNote:
    def test_reads_frontmatter_and_body(self, vault: Vault) -> None:
        note = vault.read_note("04-Knowledge/BGP.md")
        assert note.frontmatter["tags"] == ["routing"]
        assert "path-vector" in note.body

    def test_not_found_lists_folder_notes(self, vault: Vault) -> None:
        with pytest.raises(VaultError) as exc:
            vault.read_note("04-Knowledge/EIGRP.md")
        assert "BGP.md" in str(exc.value)
        assert "OSPF.md" in str(exc.value)


class TestWriteNew:
    def test_creates_file_and_parents(self, vault: Vault) -> None:
        rel = vault.write_new("02-Projects/Sub/New.md", "# New\n")
        assert rel == "02-Projects/Sub/New.md"
        assert vault.resolve(rel).read_text(encoding="utf-8") == "# New\n"

    def test_rejects_existing(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="already exists"):
            vault.write_new("04-Knowledge/BGP.md", "x")


class TestSaveExisting:
    def test_rewrites_existing(self, vault: Vault) -> None:
        vault.save_existing("04-Knowledge/OSPF.md", "# OSPF\n\nnew body\n")
        assert "new body" in vault.read_note("04-Knowledge/OSPF.md").body

    def test_rejects_missing(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="not found"):
            vault.save_existing("04-Knowledge/EIGRP.md", "x")


class TestListMd:
    def test_excludes_dot_dirs_and_assets(self, vault: Vault) -> None:
        rels = [vault.rel(p) for p in vault.list_md()]
        assert "04-Knowledge/BGP.md" in rels
        assert not any(r.startswith(".obsidian") for r in rels)
        assert not any(r.startswith("Assets") for r in rels)

    def test_folder_filter(self, vault: Vault) -> None:
        rels = [vault.rel(p) for p in vault.list_md("04-Knowledge")]
        assert rels == ["04-Knowledge/BGP.md", "04-Knowledge/OSPF.md"]

    def test_unknown_folder_raises(self, vault: Vault) -> None:
        with pytest.raises(VaultError, match="not a folder"):
            vault.list_md("99-Nope")
