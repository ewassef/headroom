from __future__ import annotations

import json
from pathlib import Path

from headroom import paths
from headroom.tool_policy import (
    TOOL_POLICY_JSON_ENV,
    TOOL_POLICY_PATH_ENV,
    append_tool_policy_audit_event,
    default_global_tool_policy_path,
    evaluate_shell_policy,
    load_tool_policy,
)


def _policy(action: str = "deny") -> dict[str, object]:
    return {
        "rules": [
            {
                "id": "curl-rule",
                "scope": "shell",
                "action": action,
                "command": "curl",
                "reason": "network egress blocked",
            }
        ]
    }


def test_load_tool_policy_prefers_env_json(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path / "workspace"))
    monkeypatch.setenv(TOOL_POLICY_JSON_ENV, json.dumps(_policy("deny")))
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    monkeypatch.setenv(paths.HEADROOM_CONFIG_DIR_ENV, str(config_dir))
    (config_dir / "tool_policy.json").write_text(json.dumps(_policy("allow")), encoding="utf-8")

    policy = load_tool_policy(cwd=tmp_path)

    assert policy is not None
    assert policy.rules[0].action == "deny"
    assert policy.source == f"env:{TOOL_POLICY_JSON_ENV}"


def test_load_tool_policy_uses_explicit_env_path(monkeypatch, tmp_path: Path) -> None:
    policy_path = tmp_path / "custom-policy.json"
    policy_path.write_text(json.dumps(_policy("require_approval")), encoding="utf-8")
    monkeypatch.setenv(TOOL_POLICY_PATH_ENV, str(policy_path))

    policy = load_tool_policy(cwd=tmp_path)

    assert policy is not None
    assert policy.rules[0].action == "require_approval"
    assert policy.source == f"path:{policy_path}"


def test_load_tool_policy_prefers_local_repo_file_over_global(monkeypatch, tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(workspace))
    project = tmp_path / "repo" / "subdir"
    project.mkdir(parents=True)
    local_policy_dir = tmp_path / "repo" / ".headroom"
    local_policy_dir.mkdir()
    (local_policy_dir / "tool_policy.json").write_text(json.dumps(_policy("deny")), encoding="utf-8")
    global_dir = default_global_tool_policy_path().parent
    global_dir.mkdir(parents=True, exist_ok=True)
    default_global_tool_policy_path().write_text(json.dumps(_policy("allow")), encoding="utf-8")

    policy = load_tool_policy(cwd=project)

    assert policy is not None
    assert policy.rules[0].action == "deny"
    assert policy.source.startswith("local:")


def test_evaluate_shell_policy_respects_report_only(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(
        TOOL_POLICY_JSON_ENV,
        json.dumps(
            {
                "mode": "report_only",
                "rules": [
                    {
                        "id": "curl-rule",
                        "scope": "shell",
                        "action": "deny",
                        "command": "curl",
                    }
                ],
            }
        ),
    )
    policy = load_tool_policy(cwd=tmp_path)

    decision = evaluate_shell_policy(
        policy,
        command_line="curl https://example.com",
        cwd=str(tmp_path),
        env={},
    )

    assert decision is not None
    assert decision.action == "deny"
    assert decision.effective_action == "allow"


def test_append_tool_policy_audit_event_writes_jsonl(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path))
    monkeypatch.setenv(TOOL_POLICY_JSON_ENV, json.dumps(_policy("deny")))
    decision = evaluate_shell_policy(
        load_tool_policy(cwd=tmp_path),
        command_line="curl https://example.com",
        cwd=str(tmp_path),
        env={},
    )

    assert decision is not None
    append_tool_policy_audit_event(decision, agent="claude", tool_name="Bash")

    record = json.loads((tmp_path / "tool_policy_audit.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert record["agent"] == "claude"
    assert record["tool_name"] == "Bash"
    assert record["matched_rule"] == "curl-rule"
