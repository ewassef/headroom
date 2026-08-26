from __future__ import annotations

import json
from pathlib import Path

from headroom import paths
from headroom.learn.audit import append_learn_audit_event


def test_append_learn_audit_event_writes_file(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path))

    append_learn_audit_event(
        agent="codex",
        project_path=tmp_path / "repo",
        model="gpt-4o",
        status="dry_run",
        dry_run=True,
        total_sessions=2,
        total_calls=10,
        total_failures=3,
        recommendation_sections=["Environment"],
        files={tmp_path / "repo" / "AGENTS.md": "hello"},
        warnings=["warn"],
    )

    record = json.loads(paths.learn_audit_path().read_text(encoding="utf-8").splitlines()[0])
    assert record["event"] == "headroom_learn_audit"
    assert record["agent"] == "codex"
    assert record["status"] == "dry_run"
    assert record["files"][0]["path"].endswith("AGENTS.md")
