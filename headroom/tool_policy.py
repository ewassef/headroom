"""Shared cross-agent tool policy loading and shell decision helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from headroom import paths

TOOL_POLICY_JSON_ENV = "HEADROOM_TOOL_POLICY_JSON"
TOOL_POLICY_PATH_ENV = "HEADROOM_TOOL_POLICY_PATH"
_LOCAL_POLICY_RELATIVE_PATH = Path(".headroom") / "tool_policy.json"
_GLOBAL_POLICY_FILE = "tool_policy.json"
_SHELL_TOOL_NAMES = {"bash", "powershell", "sh", "shell"}


@dataclass(frozen=True)
class CompiledToolPolicyRule:
    id: str
    scope: str
    action: str
    reason: str | None = None
    commands: tuple[str, ...] | None = None
    args_pattern: re.Pattern[str] | None = None
    cwd_pattern: re.Pattern[str] | None = None
    env_keys: tuple[str, ...] | None = None
    domains: tuple[str, ...] | None = None
    url_pattern: re.Pattern[str] | None = None


@dataclass(frozen=True)
class CompiledToolPolicy:
    mode: str
    default_action: str
    rules: tuple[CompiledToolPolicyRule, ...]
    serialized: str
    source: str


@dataclass(frozen=True)
class ToolPolicyDecision:
    scope: str
    action: str
    effective_action: str
    mode: str
    matched_rule_id: str | None
    reason: str | None
    resource: str
    request_hash: str
    source: str


@dataclass(frozen=True)
class HookToolRequest:
    tool_name: str
    command_line: str
    cwd: str | None
    env: Mapping[str, Any] | None
    raw_payload: Mapping[str, Any]


def default_global_tool_policy_path() -> Path:
    """Return the shared machine-level tool policy path."""

    return paths.config_dir() / _GLOBAL_POLICY_FILE


def discover_local_tool_policy_path(cwd: Path | None = None) -> Path | None:
    """Return the nearest repo-local tool policy path, if present."""

    current = (cwd or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent
    for parent in (current, *current.parents):
        candidate = parent / _LOCAL_POLICY_RELATIVE_PATH
        if candidate.exists():
            return candidate
    return None


def _load_json_text(raw: str, *, source: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid Headroom tool policy JSON from {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Headroom tool policy from {source} must be a JSON object")
    return payload


def _load_json_file(path: Path, *, source: str) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"could not read Headroom tool policy file {path} ({exc})") from exc
    return _load_json_text(raw, source=source)


def _compile_regex(source: str | None, *, field: str, rule_id: str) -> re.Pattern[str] | None:
    if not source:
        return None
    try:
        return re.compile(source)
    except re.error as exc:
        raise ValueError(
            f"invalid Headroom tool policy regex for {field} in rule {rule_id}: {exc}"
        ) from exc


def _as_tuple(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list | tuple):
        values = list(value)
    else:
        raise ValueError(f"expected string or array, got {type(value).__name__}")
    return tuple(str(entry).lower() for entry in values if str(entry).strip()) or None


def _compile_loaded_policy(payload: dict[str, Any], *, source: str) -> CompiledToolPolicy:
    rules = payload.get("rules")
    if not isinstance(rules, list):
        raise ValueError("Headroom tool policy requires a rules array")
    compiled_rules: list[CompiledToolPolicyRule] = []
    normalized_rules: list[dict[str, Any]] = []
    for index, raw_rule in enumerate(rules, start=1):
        if not isinstance(raw_rule, dict):
            raise ValueError(f"Headroom tool policy rule {index} must be a JSON object")
        rule_id = str(raw_rule.get("id") or f"rule_{index}").strip() or f"rule_{index}"
        scope = str(raw_rule.get("scope") or "")
        action = str(raw_rule.get("action") or "")
        if scope not in {"tool_call", "shell", "http"}:
            raise ValueError(f"invalid Headroom tool policy scope in rule {rule_id}: {scope!r}")
        if action not in {"allow", "deny", "require_approval"}:
            raise ValueError(f"invalid Headroom tool policy action in rule {rule_id}: {action!r}")
        compiled_rules.append(
            CompiledToolPolicyRule(
                id=rule_id,
                scope=scope,
                action=action,
                reason=(
                    str(raw_rule.get("reason")).strip() if raw_rule.get("reason") is not None else None
                )
                or None,
                commands=_as_tuple(raw_rule.get("command")),
                args_pattern=_compile_regex(
                    str(raw_rule.get("argsPattern")) if raw_rule.get("argsPattern") is not None else None,
                    field="argsPattern",
                    rule_id=rule_id,
                ),
                cwd_pattern=_compile_regex(
                    str(raw_rule.get("cwdPattern")) if raw_rule.get("cwdPattern") is not None else None,
                    field="cwdPattern",
                    rule_id=rule_id,
                ),
                env_keys=_as_tuple(raw_rule.get("envKeys")),
                domains=_as_tuple(raw_rule.get("domain")),
                url_pattern=_compile_regex(
                    str(raw_rule.get("urlPattern")) if raw_rule.get("urlPattern") is not None else None,
                    field="urlPattern",
                    rule_id=rule_id,
                ),
            )
        )
        normalized_rules.append({**raw_rule, "id": rule_id})
    default_action = str(payload.get("defaultAction") or "allow")
    if default_action not in {"allow", "deny"}:
        raise ValueError(f"invalid Headroom tool policy defaultAction: {default_action!r}")
    mode = str(payload.get("mode") or "enforce")
    if mode not in {"enforce", "report_only"}:
        raise ValueError(f"invalid Headroom tool policy mode: {mode!r}")
    serialized = json.dumps(
        {"mode": mode, "defaultAction": default_action, "rules": normalized_rules},
        sort_keys=True,
    )
    return CompiledToolPolicy(
        mode=mode,
        default_action=default_action,
        rules=tuple(compiled_rules),
        serialized=serialized,
        source=source,
    )


def load_tool_policy(
    *,
    cwd: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> CompiledToolPolicy | None:
    """Load the effective tool policy from env, local repo file, or shared config."""

    env = environ or os.environ
    raw_json = env.get(TOOL_POLICY_JSON_ENV, "").strip()
    if raw_json:
        return _compile_loaded_policy(
            _load_json_text(raw_json, source=TOOL_POLICY_JSON_ENV),
            source=f"env:{TOOL_POLICY_JSON_ENV}",
        )
    raw_path = env.get(TOOL_POLICY_PATH_ENV, "").strip()
    if raw_path:
        path = Path(raw_path).expanduser()
        return _compile_loaded_policy(
            _load_json_file(path, source=f"{TOOL_POLICY_PATH_ENV}={path}"),
            source=f"path:{path}",
        )
    local_path = discover_local_tool_policy_path(cwd)
    if local_path is not None:
        return _compile_loaded_policy(
            _load_json_file(local_path, source=str(local_path)),
            source=f"local:{local_path}",
        )
    global_path = default_global_tool_policy_path()
    if global_path.exists():
        return _compile_loaded_policy(
            _load_json_file(global_path, source=str(global_path)),
            source=f"global:{global_path}",
        )
    return None


def shell_command_binary(command_line: str) -> str:
    """Extract the shell command binary from a command line."""

    trimmed = command_line.strip()
    if not trimmed:
        return ""
    quoted = re.match(r"""^(["'])([^"']+)\1""", trimmed)
    if quoted and quoted.group(2):
        return quoted.group(2)
    return trimmed.split(None, 1)[0] if trimmed.split(None, 1) else ""


def command_matches(command: str, patterns: tuple[str, ...] | None) -> bool:
    if not patterns:
        return True
    lowered = command.strip().lower()
    normalized = Path(lowered).name
    return any(
        candidate == lowered or candidate == normalized or Path(candidate).name == normalized
        for candidate in patterns
    )


def _hash_resource(resource: str) -> str:
    return hashlib.sha256(resource.encode("utf-8")).hexdigest()[:16]


def evaluate_shell_policy(
    policy: CompiledToolPolicy | None,
    *,
    command_line: str,
    cwd: str | None = None,
    env: Mapping[str, Any] | None = None,
) -> ToolPolicyDecision | None:
    """Evaluate a shell command against the effective policy."""

    if policy is None:
        return None
    command = shell_command_binary(command_line)
    matched_rule = None
    for rule in policy.rules:
        if rule.scope not in {"tool_call", "shell"}:
            continue
        if not command_matches(command, rule.commands):
            continue
        if rule.args_pattern and not rule.args_pattern.search(command_line):
            continue
        if rule.cwd_pattern and not rule.cwd_pattern.search(cwd or ""):
            continue
        if rule.env_keys:
            input_keys = {str(key).lower() for key in (env or os.environ).keys()}
            if not all(key in input_keys for key in rule.env_keys):
                continue
        matched_rule = rule
        break
    action = matched_rule.action if matched_rule is not None else policy.default_action
    effective_action = "allow" if policy.mode == "report_only" and action != "allow" else action
    resource = command_line.strip() or command
    return ToolPolicyDecision(
        scope="shell",
        action=action,
        effective_action=effective_action,
        mode=policy.mode,
        matched_rule_id=matched_rule.id if matched_rule is not None else None,
        reason=matched_rule.reason if matched_rule is not None else None,
        resource=resource,
        request_hash=_hash_resource(resource),
        source=policy.source,
    )


def extract_hook_tool_request(payload: Mapping[str, Any] | None) -> HookToolRequest | None:
    """Normalize a PreToolUse payload into a shell-tool request, if possible."""

    if not isinstance(payload, Mapping):
        return None
    event_name = str(payload.get("hook_event_name") or payload.get("hookEventName") or "").strip()
    if event_name and event_name.lower() != "pretooluse":
        return None
    tool_name = str(payload.get("tool_name") or payload.get("toolName") or "").strip()
    if tool_name.lower() not in _SHELL_TOOL_NAMES:
        return None
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    if not isinstance(tool_input, Mapping):
        tool_input = {}
    command_line = str(tool_input.get("command") or "").strip()
    if not command_line:
        return None
    env = tool_input.get("env")
    return HookToolRequest(
        tool_name=tool_name,
        command_line=command_line,
        cwd=str(payload.get("cwd") or tool_input.get("cwd") or "").strip() or None,
        env=env if isinstance(env, Mapping) else None,
        raw_payload=payload,
    )


def format_decision_reason(decision: ToolPolicyDecision) -> str:
    """Return a human-readable explanation for hook consumers."""

    prefix = "Headroom tool policy requires approval for" if decision.action == "require_approval" else "Headroom tool policy denied"
    suffix = f" (rule={decision.matched_rule_id})" if decision.matched_rule_id else ""
    if decision.reason:
        suffix += f": {decision.reason}"
    return f"{prefix} {decision.scope} target {decision.resource}{suffix}"


def append_tool_policy_audit_event(
    decision: ToolPolicyDecision,
    *,
    agent: str,
    tool_name: str,
) -> None:
    """Persist a tool-policy decision for auditability. Best-effort only."""

    if paths.process_is_stateless():
        return
    record = {
        "event": "headroom_tool_policy_decision",
        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "agent": agent,
        "tool_name": tool_name,
        "scope": decision.scope,
        "action": decision.action,
        "effective_action": decision.effective_action,
        "mode": decision.mode,
        "matched_rule": decision.matched_rule_id or "",
        "reason": decision.reason or "",
        "resource": decision.resource,
        "request_hash": decision.request_hash,
        "source": decision.source,
    }
    try:
        target = paths.ensure_workspace_dir() / "tool_policy_audit.jsonl"
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        return
