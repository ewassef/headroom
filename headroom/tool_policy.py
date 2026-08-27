"""Shared cross-agent tool policy loading and shell decision helpers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from headroom import paths
from headroom.fsutil import write_text

TOOL_POLICY_JSON_ENV = "HEADROOM_TOOL_POLICY_JSON"
TOOL_POLICY_PATH_ENV = "HEADROOM_TOOL_POLICY_PATH"
TOOL_POLICY_URL_ENV = "HEADROOM_TOOL_POLICY_URL"
TOOL_POLICY_TOKEN_ENV = "HEADROOM_TOOL_POLICY_TOKEN"
TOOL_POLICY_REFRESH_SECONDS_ENV = "HEADROOM_TOOL_POLICY_REFRESH_SECONDS"
_LOCAL_POLICY_RELATIVE_PATH = Path(".headroom") / "tool_policy.json"
_GLOBAL_POLICY_FILE = "tool_policy.json"
_REMOTE_CACHE_DIR = "policy-cache"
_POLICY_VERSION = 1
_DEFAULT_REFRESH_SECONDS = 300
_MAX_REFRESH_SECONDS = 3600
_REMOTE_TIMEOUT_SECONDS = 5
_MAX_REMOTE_POLICY_BYTES = 1024 * 1024
_SHELL_TOOL_NAMES = {"bash", "powershell", "sh", "shell"}
_SHELL_OPERATORS = {";", "&&", "||", "|", "&"}
_COMMAND_WRAPPERS = {"command", "env", "nohup", "sudo", "time"}
_SHELL_WRAPPERS = {"bash", "cmd", "dash", "ksh", "powershell", "pwsh", "sh", "zsh"}
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPER_OPTIONS_WITH_VALUE = {
    "env": {"-C", "--chdir", "-S", "--split-string", "-u", "--unset"},
    "sudo": {
        "-C",
        "--close-from",
        "-g",
        "--group",
        "-h",
        "--host",
        "-p",
        "--prompt",
        "-R",
        "--chroot",
        "-r",
        "--role",
        "-T",
        "--command-timeout",
        "-t",
        "--type",
        "-u",
        "--user",
    },
    "time": {"-f", "--format", "-o", "--output"},
}
logger = logging.getLogger(__name__)


class ToolPolicyUnavailableError(ValueError):
    """Raised when a configured remote policy cannot be loaded safely."""


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_remote_policy_request(request: urllib.request.Request, *, timeout: int):
    opener = urllib.request.build_opener(_RejectRedirectHandler())
    return opener.open(request, timeout=timeout)


@dataclass(frozen=True)
class CompiledToolPolicyRule:
    id: str
    scope: str
    action: str
    reason: str | None = None
    tools: tuple[str, ...] | None = None
    commands: tuple[str, ...] | None = None
    args_pattern: re.Pattern[str] | None = None
    cwd_pattern: re.Pattern[str] | None = None
    env_keys: tuple[str, ...] | None = None
    domains: tuple[str, ...] | None = None
    url_pattern: re.Pattern[str] | None = None


@dataclass(frozen=True)
class CompiledToolPolicy:
    version: int
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
    tool_input: Mapping[str, Any]
    cwd: str | None
    env: Mapping[str, Any] | None
    raw_payload: Mapping[str, Any]


def default_global_tool_policy_path() -> Path:
    """Return the shared machine-level tool policy path."""

    return paths.config_dir() / _GLOBAL_POLICY_FILE


def remote_tool_policy_cache_path(url: str, token: str = "") -> Path:
    """Return the cache path shared by all integrations for a policy URL."""

    digest = hashlib.sha256(f"{url}\0{token}".encode()).hexdigest()
    return paths.workspace_dir() / _REMOTE_CACHE_DIR / f"{digest}.json"


def _remote_policy_url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def tool_policy_refresh_seconds(environ: Mapping[str, str] | None = None) -> int:
    """Return the bounded remote refresh interval.

    The interval may only extend the five-minute default up to one hour. Invalid,
    shorter, or larger values revert to the safe default.
    """

    env = environ or os.environ
    raw = env.get(TOOL_POLICY_REFRESH_SECONDS_ENV, "").strip()
    if not raw:
        return _DEFAULT_REFRESH_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_REFRESH_SECONDS
    if _DEFAULT_REFRESH_SECONDS <= value <= _MAX_REFRESH_SECONDS:
        return value
    return _DEFAULT_REFRESH_SECONDS


def _validate_remote_policy_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    hostname = (parsed.hostname or "").lower()
    try:
        is_loopback = ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        is_loopback = hostname == "localhost"
    if parsed.scheme == "https" and hostname:
        return
    if parsed.scheme == "http" and is_loopback:
        return
    raise ValueError(
        f"{TOOL_POLICY_URL_ENV} must use HTTPS; HTTP is only allowed for loopback services"
    )


def _remote_policy_source(url: str, *, cached: bool = False) -> str:
    hostname = urllib.parse.urlsplit(url).hostname or "remote"
    prefix = "remote-cache" if cached else "remote"
    return f"{prefix}:{hostname.lower()}"


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
    version = payload.get("version", _POLICY_VERSION)
    if version != _POLICY_VERSION:
        raise ValueError(
            f"unsupported Headroom tool policy version from {source}: {version!r}; "
            f"expected {_POLICY_VERSION}"
        )
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
                    str(raw_rule.get("reason")).strip()
                    if raw_rule.get("reason") is not None
                    else None
                )
                or None,
                tools=_as_tuple(raw_rule.get("tool")),
                commands=_as_tuple(raw_rule.get("command")),
                args_pattern=_compile_regex(
                    str(raw_rule.get("argsPattern"))
                    if raw_rule.get("argsPattern") is not None
                    else None,
                    field="argsPattern",
                    rule_id=rule_id,
                ),
                cwd_pattern=_compile_regex(
                    str(raw_rule.get("cwdPattern"))
                    if raw_rule.get("cwdPattern") is not None
                    else None,
                    field="cwdPattern",
                    rule_id=rule_id,
                ),
                env_keys=_as_tuple(raw_rule.get("envKeys")),
                domains=_as_tuple(raw_rule.get("domain")),
                url_pattern=_compile_regex(
                    str(raw_rule.get("urlPattern"))
                    if raw_rule.get("urlPattern") is not None
                    else None,
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
        {
            "version": _POLICY_VERSION,
            "mode": mode,
            "defaultAction": default_action,
            "rules": normalized_rules,
        },
        sort_keys=True,
    )
    return CompiledToolPolicy(
        version=_POLICY_VERSION,
        mode=mode,
        default_action=default_action,
        rules=tuple(compiled_rules),
        serialized=serialized,
        source=source,
    )


def _read_remote_cache(cache_path: Path, *, url: str) -> dict[str, Any] | None:
    if not cache_path.exists():
        return None
    try:
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("ignoring unreadable Headroom tool policy cache %s: %s", cache_path, exc)
        return None
    if not isinstance(payload, dict) or payload.get("url_hash") != _remote_policy_url_hash(url):
        logger.warning("ignoring mismatched Headroom tool policy cache %s", cache_path)
        return None
    if payload.get("cache_version") != 2:
        logger.warning("ignoring unsupported Headroom tool policy cache %s", cache_path)
        return None
    if not isinstance(payload.get("policy"), dict):
        logger.warning("ignoring invalid Headroom tool policy cache %s", cache_path)
        return None
    return payload


def _write_remote_cache(cache_path: Path, payload: dict[str, Any]) -> None:
    if paths.process_is_stateless():
        return
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    write_text(cache_path, json.dumps(payload, sort_keys=True) + "\n")


def _load_remote_tool_policy(
    url: str,
    *,
    environ: Mapping[str, str],
    now: float,
) -> CompiledToolPolicy:
    token = environ.get(TOOL_POLICY_TOKEN_ENV, "").strip()
    cache_path = remote_tool_policy_cache_path(url, token)
    cache = _read_remote_cache(cache_path, url=url)
    refresh_seconds = tool_policy_refresh_seconds(environ)
    if cache is not None:
        fetched_at = cache.get("fetched_at")
        if isinstance(fetched_at, int | float):
            age = now - float(fetched_at)
            if 0 <= age < refresh_seconds:
                return _compile_loaded_policy(
                    cache["policy"], source=_remote_policy_source(url, cached=True)
                )

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cache is not None and isinstance(cache.get("etag"), str) and cache["etag"]:
        headers["If-None-Match"] = cache["etag"]
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _open_remote_policy_request(request, timeout=_REMOTE_TIMEOUT_SECONDS) as response:
            body = response.read(_MAX_REMOTE_POLICY_BYTES + 1)
            if len(body) > _MAX_REMOTE_POLICY_BYTES:
                raise ValueError("remote Headroom tool policy exceeds 1 MiB")
            raw = body.decode("utf-8")
            remote_source = _remote_policy_source(url)
            policy_payload = _load_json_text(raw, source=remote_source)
            compiled = _compile_loaded_policy(policy_payload, source=remote_source)
            _write_remote_cache(
                cache_path,
                {
                    "cache_version": 2,
                    "url_hash": _remote_policy_url_hash(url),
                    "etag": response.headers.get("ETag", ""),
                    "fetched_at": now,
                    "policy": json.loads(compiled.serialized),
                },
            )
            return compiled
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and cache is not None:
            cache["fetched_at"] = now
            _write_remote_cache(cache_path, cache)
            return _compile_loaded_policy(
                cache["policy"], source=_remote_policy_source(url, cached=True)
            )
        raise ToolPolicyUnavailableError(
            f"Headroom tool policy service {_remote_policy_source(url)} returned HTTP {exc.code}"
        ) from exc
    except (OSError, UnicodeError, urllib.error.URLError, ValueError) as exc:
        if isinstance(exc, ToolPolicyUnavailableError):
            raise
        raise ToolPolicyUnavailableError(
            f"Headroom tool policy service {_remote_policy_source(url)} is unavailable "
            f"({type(exc).__name__})"
        ) from exc


def load_tool_policy(
    *,
    cwd: Path | None = None,
    environ: Mapping[str, str] | None = None,
    now: float | None = None,
) -> CompiledToolPolicy | None:
    """Load one effective policy from inline, file, remote, or discovered config.

    Explicit operator-controlled sources take precedence. A machine-level policy
    is authoritative over repository configuration so a checkout cannot weaken
    workstation controls.
    """

    env = environ or os.environ
    raw_json = env.get(TOOL_POLICY_JSON_ENV, "").strip()
    if raw_json:
        return _compile_loaded_policy(
            _load_json_text(raw_json, source=TOOL_POLICY_JSON_ENV),
            source=f"env:{TOOL_POLICY_JSON_ENV}",
        )
    raw_path = env.get(TOOL_POLICY_PATH_ENV, "").strip()
    if raw_path:
        policy_path = Path(raw_path).expanduser()
        return _compile_loaded_policy(
            _load_json_file(policy_path, source=f"{TOOL_POLICY_PATH_ENV}={policy_path}"),
            source=f"path:{policy_path}",
        )
    remote_url = env.get(TOOL_POLICY_URL_ENV, "").strip()
    if remote_url:
        _validate_remote_policy_url(remote_url)
        return _load_remote_tool_policy(
            remote_url,
            environ=env,
            now=time.time() if now is None else now,
        )
    global_path = default_global_tool_policy_path()
    if global_path.exists():
        return _compile_loaded_policy(
            _load_json_file(global_path, source=str(global_path)),
            source=f"global:{global_path}",
        )
    local_path = discover_local_tool_policy_path(cwd)
    if local_path is not None:
        return _compile_loaded_policy(
            _load_json_file(local_path, source=str(local_path)),
            source=f"local:{local_path}",
        )
    return None


def _shell_tokens(command_line: str) -> list[str]:
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(command_line):
        char = command_line[index]
        if quote is not None:
            if char == quote:
                quote = None
            elif char == "\\" and quote == '"' and index + 1 < len(command_line):
                index += 1
                current.append(command_line[index])
            else:
                current.append(char)
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char in {"\r", "\n"}:
            if current:
                tokens.append("".join(current))
                current = []
            tokens.append(";")
            if char == "\r" and index + 1 < len(command_line) and command_line[index + 1] == "\n":
                index += 1
            index += 1
            continue
        if char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
            index += 1
            continue
        if char in {";", "&", "|"}:
            if current:
                tokens.append("".join(current))
                current = []
            if index + 1 < len(command_line) and command_line[index + 1] == char:
                tokens.append(char * 2)
                index += 2
            else:
                tokens.append(char)
                index += 1
            continue
        current.append(char)
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


def _shell_command_substitutions(command_line: str) -> tuple[str, ...]:
    substitutions: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(command_line):
        char = command_line[index]
        if char == "\\" and quote != "'" and index + 1 < len(command_line):
            index += 2
            continue
        if char == "'" and quote != '"':
            quote = None if quote == "'" else "'"
            index += 1
            continue
        if char == '"' and quote != "'":
            quote = None if quote == '"' else '"'
            index += 1
            continue
        if quote != "'" and char == "`":
            end = index + 1
            while end < len(command_line):
                if command_line[end] == "\\":
                    end += 2
                    continue
                if command_line[end] == "`":
                    substitutions.append(command_line[index + 1 : end])
                    index = end + 1
                    break
                end += 1
            else:
                index += 1
            continue
        if quote != "'" and command_line.startswith("$(", index):
            if command_line.startswith("$((", index):
                index += 3
                continue
            depth = 1
            end = index + 2
            nested_quote: str | None = None
            while end < len(command_line):
                nested_char = command_line[end]
                if nested_char == "\\" and nested_quote != "'" and end + 1 < len(command_line):
                    end += 2
                    continue
                if nested_char in {"'", '"'}:
                    if nested_quote is None:
                        nested_quote = nested_char
                    elif nested_quote == nested_char:
                        nested_quote = None
                    end += 1
                    continue
                if nested_quote is None:
                    if command_line.startswith("$(", end):
                        depth += 1
                        end += 2
                        continue
                    if nested_char == ")":
                        depth -= 1
                        if depth == 0:
                            substitutions.append(command_line[index + 2 : end])
                            index = end + 1
                            break
                end += 1
            else:
                index += 2
            continue
        index += 1
    return tuple(substitutions)


def _segment_binary(tokens: list[str]) -> tuple[str | None, tuple[str, ...]]:
    index = 0
    nested_commands: list[str] = []
    while index < len(tokens) and _ENV_ASSIGNMENT.match(tokens[index]):
        index += 1
    while index < len(tokens):
        command = Path(tokens[index].lower()).name
        if command not in _COMMAND_WRAPPERS:
            break
        index += 1
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                index += 1
                break
            if _ENV_ASSIGNMENT.match(token):
                index += 1
                continue
            option_name = token.split("=", 1)[0]
            if token.startswith("-"):
                index += 1
                if (
                    "=" not in token
                    and option_name in _WRAPPER_OPTIONS_WITH_VALUE.get(command, set())
                    and index < len(tokens)
                ):
                    if command == "env" and option_name in {"-S", "--split-string"}:
                        nested_commands.append(tokens[index])
                    index += 1
                continue
            break
    if index >= len(tokens):
        return None, tuple(nested_commands)
    command = tokens[index]
    normalized = Path(command.lower()).name
    if normalized in _SHELL_WRAPPERS:
        for flag_index in range(index + 1, len(tokens) - 1):
            if tokens[flag_index].lower() in {"-c", "/c", "-command"}:
                nested_commands.append(tokens[flag_index + 1])
                break
    return command, tuple(nested_commands)


def shell_command_binaries(command_line: str) -> tuple[str, ...]:
    """Extract executable candidates from compound and shell-wrapped commands."""

    tokens = _shell_tokens(command_line)
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in _SHELL_OPERATORS:
            if segments[-1]:
                segments.append([])
            continue
        segments[-1].append(token)
    binaries: list[str] = []
    for segment in segments:
        command, nested_commands = _segment_binary(segment)
        if command:
            binaries.append(command)
        for nested in nested_commands:
            binaries.extend(shell_command_binaries(nested))
    for substitution in _shell_command_substitutions(command_line):
        binaries.extend(shell_command_binaries(substitution))
    return tuple(dict.fromkeys(binaries))


def shell_command_binary(command_line: str) -> str:
    """Return the first executable candidate for backward compatibility."""

    return next(iter(shell_command_binaries(command_line)), "")


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
    tool_name: str | None = None,
    cwd: str | None = None,
    env: Mapping[str, Any] | None = None,
) -> ToolPolicyDecision | None:
    """Evaluate a shell command against the effective policy."""

    if policy is None:
        return None
    commands = shell_command_binaries(command_line)
    command = commands[0] if commands else ""
    matched_rule = None
    for rule in policy.rules:
        if rule.scope not in {"tool_call", "shell"}:
            continue
        if rule.scope == "tool_call" and not command_matches(tool_name or "", rule.tools):
            continue
        if not any(command_matches(candidate, rule.commands) for candidate in commands or ("",)):
            continue
        if rule.args_pattern and not rule.args_pattern.search(command_line):
            continue
        if rule.cwd_pattern and not rule.cwd_pattern.search(cwd or ""):
            continue
        if rule.env_keys:
            input_env = env if env is not None else os.environ
            input_keys = {str(key).lower() for key in input_env}
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


def evaluate_tool_policy(
    policy: CompiledToolPolicy | None,
    *,
    tool_name: str,
    tool_input: Mapping[str, Any],
    cwd: str | None = None,
    env: Mapping[str, Any] | None = None,
) -> ToolPolicyDecision | None:
    """Evaluate a native agent tool call using the shared policy semantics."""

    command_line = str(tool_input.get("command") or "").strip()
    if tool_name.lower() in _SHELL_TOOL_NAMES and command_line:
        return evaluate_shell_policy(
            policy,
            command_line=command_line,
            tool_name=tool_name,
            cwd=cwd,
            env=env,
        )
    if policy is None:
        return None
    args_text = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), default=str)
    matched_rule = None
    for rule in policy.rules:
        if rule.scope != "tool_call":
            continue
        if not command_matches(tool_name, rule.tools):
            continue
        if rule.commands:
            continue
        if rule.args_pattern and not rule.args_pattern.search(args_text):
            continue
        if rule.cwd_pattern and not rule.cwd_pattern.search(cwd or ""):
            continue
        if rule.env_keys:
            input_env = env if env is not None else os.environ
            input_keys = {str(key).lower() for key in input_env}
            if not all(key in input_keys for key in rule.env_keys):
                continue
        matched_rule = rule
        break
    action = matched_rule.action if matched_rule is not None else policy.default_action
    effective_action = "allow" if policy.mode == "report_only" and action != "allow" else action
    resource = f"{tool_name} {args_text}"
    return ToolPolicyDecision(
        scope="tool_call",
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
    if not tool_name:
        return None
    tool_input = (
        payload.get("tool_input") or payload.get("toolInput") or payload.get("toolArgs") or {}
    )
    if not isinstance(tool_input, Mapping):
        tool_input = {}
    command_line = str(tool_input.get("command") or "").strip()
    env = tool_input.get("env")
    return HookToolRequest(
        tool_name=tool_name,
        command_line=command_line,
        tool_input=tool_input,
        cwd=str(payload.get("cwd") or tool_input.get("cwd") or "").strip() or None,
        env=env if isinstance(env, Mapping) else None,
        raw_payload=payload,
    )


def format_decision_reason(decision: ToolPolicyDecision) -> str:
    """Return a human-readable explanation for hook consumers."""

    prefix = (
        "Headroom tool policy requires approval for"
        if decision.action == "require_approval"
        else "Headroom tool policy denied"
    )
    suffix = f" (rule={decision.matched_rule_id})" if decision.matched_rule_id else ""
    if decision.reason:
        suffix += f": {decision.reason}"
    return f"{prefix} {decision.scope} target {decision.resource}{suffix}"


def _audit_resource(decision: ToolPolicyDecision) -> str:
    if decision.scope == "shell":
        return ",".join(shell_command_binaries(decision.resource))
    if decision.scope == "tool_call":
        return decision.resource.split(" ", 1)[0]
    try:
        return urllib.parse.urlsplit(decision.resource).hostname or decision.scope
    except ValueError:
        return decision.scope


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
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent": agent,
        "tool_name": tool_name,
        "scope": decision.scope,
        "action": decision.action,
        "effective_action": decision.effective_action,
        "mode": decision.mode,
        "matched_rule": decision.matched_rule_id or "",
        "reason": decision.reason or "",
        "resource": _audit_resource(decision),
        "request_hash": decision.request_hash,
        "source": decision.source,
    }
    try:
        target = paths.ensure_workspace_dir() / "tool_policy_audit.jsonl"
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError:
        return
