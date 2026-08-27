from __future__ import annotations

import json
import urllib.error
import urllib.request
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from headroom import paths
from headroom import tool_policy as tool_policy_module
from headroom.tool_policy import (
    TOOL_POLICY_JSON_ENV,
    TOOL_POLICY_PATH_ENV,
    TOOL_POLICY_REFRESH_SECONDS_ENV,
    TOOL_POLICY_TOKEN_ENV,
    TOOL_POLICY_URL_ENV,
    ToolPolicyUnavailableError,
    append_tool_policy_audit_event,
    default_global_tool_policy_path,
    evaluate_shell_policy,
    evaluate_tool_policy,
    load_tool_policy,
    remote_tool_policy_cache_path,
    shell_command_binaries,
    tool_policy_refresh_seconds,
)


def _policy(action: str = "deny") -> dict[str, object]:
    return {
        "version": 1,
        "rules": [
            {
                "id": "curl-rule",
                "scope": "shell",
                "action": action,
                "command": "curl",
                "reason": "network egress blocked",
            }
        ],
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


def test_load_tool_policy_prefers_global_file_over_repo_file(monkeypatch, tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(workspace))
    project = tmp_path / "repo" / "subdir"
    project.mkdir(parents=True)
    local_policy_dir = tmp_path / "repo" / ".headroom"
    local_policy_dir.mkdir()
    (local_policy_dir / "tool_policy.json").write_text(
        json.dumps(_policy("deny")), encoding="utf-8"
    )
    global_dir = default_global_tool_policy_path().parent
    global_dir.mkdir(parents=True, exist_ok=True)
    default_global_tool_policy_path().write_text(json.dumps(_policy("allow")), encoding="utf-8")

    policy = load_tool_policy(cwd=project)

    assert policy is not None
    assert policy.rules[0].action == "allow"
    assert policy.source.startswith("global:")


def test_load_tool_policy_uses_repo_file_without_operator_policy(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path / "workspace"))
    monkeypatch.setenv(paths.HEADROOM_CONFIG_DIR_ENV, str(tmp_path / "config"))
    project = tmp_path / "repo" / "subdir"
    project.mkdir(parents=True)
    local_policy_dir = tmp_path / "repo" / ".headroom"
    local_policy_dir.mkdir()
    (local_policy_dir / "tool_policy.json").write_text(json.dumps(_policy()), encoding="utf-8")

    policy = load_tool_policy(cwd=project)

    assert policy is not None
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


@pytest.mark.parametrize(
    ("command_line", "expected"),
    [
        ("curl https://example.com", ("curl",)),
        ("echo ok; curl https://example.com", ("echo", "curl")),
        ("echo ok\ncurl https://example.com", ("echo", "curl")),
        ("env API_KEY=x curl https://example.com", ("curl",)),
        ("env -S 'curl https://example.com'", ("curl",)),
        ("sudo -u root curl https://example.com", ("curl",)),
        ('bash -c "curl https://example.com"', ("bash", "curl")),
        ("echo $(curl https://example.com)", ("echo", "curl")),
        ("echo `curl https://example.com`", ("echo", "curl")),
        ("echo '$(curl https://example.com)'", ("echo",)),
        (
            'powershell -Command "Write-Host ok; curl https://example.com"',
            ("powershell", "Write-Host", "curl"),
        ),
    ],
)
def test_shell_command_binaries_finds_wrapped_and_compound_commands(
    command_line: str,
    expected: tuple[str, ...],
) -> None:
    assert shell_command_binaries(command_line) == expected


def test_evaluate_shell_policy_denies_command_later_in_compound_line(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(TOOL_POLICY_JSON_ENV, json.dumps(_policy()))

    decision = evaluate_shell_policy(
        load_tool_policy(cwd=tmp_path),
        command_line="echo ok && curl https://example.com",
        cwd=str(tmp_path),
        env={},
    )

    assert decision is not None
    assert decision.action == "deny"
    assert decision.matched_rule_id == "curl-rule"


def test_evaluate_tool_policy_denies_matching_native_tool(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(
        TOOL_POLICY_JSON_ENV,
        json.dumps(
            {
                "version": 1,
                "rules": [
                    {
                        "id": "deny-prod-write",
                        "scope": "tool_call",
                        "action": "deny",
                        "tool": ["write_file", "apply_patch"],
                        "argsPattern": "production",
                    }
                ],
            }
        ),
    )

    decision = evaluate_tool_policy(
        load_tool_policy(cwd=tmp_path),
        tool_name="write_file",
        tool_input={"path": "production.env"},
        cwd=str(tmp_path),
        env={},
    )

    assert decision is not None
    assert decision.action == "deny"
    assert decision.scope == "tool_call"
    assert decision.matched_rule_id == "deny-prod-write"


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], *, etag: str = '"policy-1"') -> None:
        self._raw = json.dumps(payload).encode()
        self.headers = Message()
        self.headers["ETag"] = etag

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self._raw if size < 0 else self._raw[:size]


def test_remote_policy_fetches_with_auth_and_reuses_fresh_cache(
    monkeypatch,
    tmp_path: Path,
) -> None:
    url = "https://policy.example/v1/tool-policy"
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path))
    env = {
        TOOL_POLICY_URL_ENV: url,
        TOOL_POLICY_TOKEN_ENV: "secret-token",
    }
    requests: list[Any] = []

    def fake_urlopen(request, *, timeout):
        requests.append((request, timeout))
        return _FakeResponse(_policy())

    monkeypatch.setattr("headroom.tool_policy._open_remote_policy_request", fake_urlopen)

    fetched = load_tool_policy(cwd=tmp_path, environ=env, now=1_000)
    cached = load_tool_policy(cwd=tmp_path, environ=env, now=1_100)

    assert fetched is not None and fetched.source == "remote:policy.example"
    assert cached is not None and cached.source == "remote-cache:policy.example"
    assert len(requests) == 1
    assert requests[0][0].get_header("Authorization") == "Bearer secret-token"
    cache = json.loads(
        remote_tool_policy_cache_path(url, "secret-token").read_text(encoding="utf-8")
    )
    assert cache["cache_version"] == 2
    assert "url" not in cache
    assert cache["etag"] == '"policy-1"'


def test_remote_policy_revalidates_expired_cache_with_etag(
    monkeypatch,
    tmp_path: Path,
) -> None:
    url = "https://policy.example/v1/tool-policy"
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path))
    env = {TOOL_POLICY_URL_ENV: url}
    calls = 0

    def fake_urlopen(request, *, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            return _FakeResponse(_policy())
        assert request.get_header("If-none-match") == '"policy-1"'
        raise urllib.error.HTTPError(url, 304, "Not Modified", Message(), None)

    monkeypatch.setattr("headroom.tool_policy._open_remote_policy_request", fake_urlopen)

    load_tool_policy(cwd=tmp_path, environ=env, now=1_000)
    policy = load_tool_policy(cwd=tmp_path, environ=env, now=1_301)

    assert policy is not None and policy.source == "remote-cache:policy.example"
    assert calls == 2


def test_remote_policy_cache_is_scoped_to_bearer_credential(monkeypatch, tmp_path: Path) -> None:
    url = "https://policy.example/v1/tool-policy"
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path))
    calls = 0

    def fake_urlopen(request, *, timeout):
        nonlocal calls
        calls += 1
        return _FakeResponse(_policy())

    monkeypatch.setattr("headroom.tool_policy._open_remote_policy_request", fake_urlopen)

    load_tool_policy(
        cwd=tmp_path,
        environ={TOOL_POLICY_URL_ENV: url, TOOL_POLICY_TOKEN_ENV: "tenant-a"},
        now=1_000,
    )
    load_tool_policy(
        cwd=tmp_path,
        environ={TOOL_POLICY_URL_ENV: url, TOOL_POLICY_TOKEN_ENV: "tenant-b"},
        now=1_001,
    )

    assert calls == 2
    assert remote_tool_policy_cache_path(url, "tenant-a") != remote_tool_policy_cache_path(
        url, "tenant-b"
    )


def test_remote_policy_revalidates_cache_timestamp_from_future(
    monkeypatch,
    tmp_path: Path,
) -> None:
    url = "https://policy.example/v1/tool-policy"
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path))
    env = {TOOL_POLICY_URL_ENV: url}
    calls = 0

    def fake_urlopen(request, *, timeout):
        nonlocal calls
        calls += 1
        return _FakeResponse(_policy(), etag=f'"policy-{calls}"')

    monkeypatch.setattr("headroom.tool_policy._open_remote_policy_request", fake_urlopen)

    load_tool_policy(cwd=tmp_path, environ=env, now=2_000)
    load_tool_policy(cwd=tmp_path, environ=env, now=1_000)

    assert calls == 2


def test_remote_policy_fails_closed_when_expired_and_service_is_unavailable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    url = "https://policy.example/v1/tool-policy"
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path))
    env = {TOOL_POLICY_URL_ENV: url}
    monkeypatch.setattr(
        "headroom.tool_policy._open_remote_policy_request",
        lambda request, timeout: _FakeResponse(_policy()),
    )
    load_tool_policy(cwd=tmp_path, environ=env, now=1_000)
    monkeypatch.setattr(
        "headroom.tool_policy._open_remote_policy_request",
        lambda request, timeout: (_ for _ in ()).throw(urllib.error.URLError("offline")),
    )

    with pytest.raises(ToolPolicyUnavailableError, match="unavailable"):
        load_tool_policy(cwd=tmp_path, environ=env, now=1_301)


def test_remote_policy_rejects_insecure_non_loopback_url(tmp_path: Path) -> None:
    for url in (
        "http://policy.example/v1/tool-policy",
        "http://127.attacker.example/v1/tool-policy",
    ):
        with pytest.raises(ValueError, match="must use HTTPS"):
            load_tool_policy(
                cwd=tmp_path,
                environ={TOOL_POLICY_URL_ENV: url},
                now=1_000,
            )


def test_explicit_empty_environment_does_not_use_process_environment(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv(
        TOOL_POLICY_JSON_ENV,
        json.dumps(
            {
                "version": 1,
                "defaultAction": "deny",
                "rules": [
                    {
                        "id": "ci-only",
                        "scope": "tool_call",
                        "action": "allow",
                        "tool": "Read",
                        "envKeys": ["CI"],
                    }
                ],
            }
        ),
    )

    decision = evaluate_tool_policy(
        load_tool_policy(cwd=tmp_path), tool_name="Read", tool_input={}, env={}
    )

    assert decision is not None
    assert decision.action == "deny"


def test_remote_policy_redirects_are_not_followed() -> None:
    request = urllib.request.Request("https://policy.example/v1/tool-policy")
    redirected = tool_policy_module._RejectRedirectHandler().redirect_request(
        request,
        None,
        302,
        "Found",
        Message(),
        "https://other.example/policy",
    )

    assert redirected is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", 300),
        ("300", 300),
        ("900", 900),
        ("3600", 3600),
        ("299", 300),
        ("3601", 300),
        ("invalid", 300),
    ],
)
def test_tool_policy_refresh_seconds_is_bounded(raw: str, expected: int) -> None:
    assert tool_policy_refresh_seconds({TOOL_POLICY_REFRESH_SECONDS_ENV: raw}) == expected


def test_shared_tool_policy_conformance_cases(monkeypatch, tmp_path: Path) -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "tool_policy_conformance.json"
    cases = json.loads(fixture_path.read_text(encoding="utf-8"))
    for case in cases:
        monkeypatch.setenv(TOOL_POLICY_JSON_ENV, json.dumps(case["policy"]))
        request = case["request"]
        decision = evaluate_tool_policy(
            load_tool_policy(cwd=tmp_path),
            tool_name=request["tool"],
            tool_input=request["input"],
            cwd=request.get("cwd", str(tmp_path)),
            env=request.get("env", {}),
        )
        expected = case["expected"]
        assert decision is not None, case["name"]
        assert decision.action == expected["action"], case["name"]
        assert decision.effective_action == expected["effectiveAction"], case["name"]
        assert decision.matched_rule_id == expected["matchedRule"], case["name"]


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

    record = json.loads(
        (tmp_path / "tool_policy_audit.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert record["agent"] == "claude"
    assert record["tool_name"] == "Bash"
    assert record["matched_rule"] == "curl-rule"
    assert record["resource"] == "curl"
    assert "example.com" not in json.dumps(record)


def test_remote_policy_audit_source_omits_url_secrets(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv(paths.HEADROOM_WORKSPACE_DIR_ENV, str(tmp_path))
    url = "https://user:password@policy.example/v1/tool-policy?tenant=secret"
    monkeypatch.setattr(
        "headroom.tool_policy._open_remote_policy_request",
        lambda request, timeout: _FakeResponse(_policy()),
    )
    decision = evaluate_shell_policy(
        load_tool_policy(cwd=tmp_path, environ={TOOL_POLICY_URL_ENV: url}, now=1_000),
        command_line="curl https://example.com",
        env={},
    )

    assert decision is not None
    append_tool_policy_audit_event(decision, agent="claude", tool_name="Bash")
    audit = (tmp_path / "tool_policy_audit.jsonl").read_text(encoding="utf-8")
    assert "policy.example" in audit
    assert "password" not in audit
    assert "tenant" not in audit
    assert "secret" not in audit
