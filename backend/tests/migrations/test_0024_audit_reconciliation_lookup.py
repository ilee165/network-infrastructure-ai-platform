"""Migration 0024 adds the set-wise CR reconciliation lookup index."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory


def test_0024_is_expand_only_composite_lookup_index() -> None:
    backend = Path(__file__).resolve().parents[2]
    cfg = Config()
    cfg.set_main_option("script_location", str(backend / "alembic"))
    script = ScriptDirectory.from_config(cfg)
    revision = script.get_revision("0024")
    assert revision is not None
    assert revision.down_revision == "0023"
    source = Path(revision.path).read_text()
    assert '"ix_audit_log_cr_reconciliation_lookup"' in source
    assert '["target_type", "target_id", "action", "reasoning_trace_id"]' in source
    assert "unique=True" not in source
    upgrade = source.split("def upgrade()", 1)[1].split("def downgrade()", 1)[0]
    assert "drop_" not in upgrade
