# Headroom agent hooks

This plugin exposes lightweight startup hooks for Claude Code, GitHub Copilot CLI, and Codex.

The hooks call:

```bash
headroom init hook ensure
```

That hidden helper checks for a matching durable `headroom init` deployment and starts it if needed.

The same hook entrypoint also evaluates `PreToolUse` shell requests when the host sends them, so one Headroom policy can control multiple coding agents.

## Shared tool policy control

Hook-based agents resolve policy from the same canonical sources as the OpenCode plugin:

1. `HEADROOM_TOOL_POLICY_JSON`
2. `HEADROOM_TOOL_POLICY_PATH`
3. nearest repo `.headroom/tool_policy.json`
4. `~/.headroom/config/tool_policy.json`

Example machine-level policy:

```json
{
  "mode": "enforce",
  "rules": [
    {
      "id": "ask-before-git-push",
      "scope": "shell",
      "action": "require_approval",
      "command": "git",
      "argsPattern": "\\bpush\\b"
    },
    {
      "id": "deny-curl-posts",
      "scope": "shell",
      "action": "deny",
      "command": "curl",
      "argsPattern": "\\b-X\\s+POST\\b"
    }
  ]
}
```

Hook hosts receive native approval output:

- Claude Code / GitHub Copilot CLI: `permissionDecision=allow|deny|ask`
- Codex: `hookSpecificOutput.permissionDecision=allow|deny|ask`

Every evaluated decision is appended to `~/.headroom/tool_policy_audit.jsonl` with the agent name, matched rule, resource, and effective action.
