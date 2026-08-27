# headroom-opencode

OpenCode integration helpers for Headroom. The package supports two integration paths:

1. Provider config helpers used by `headroom wrap opencode` and persistent installs.
2. A native OpenCode plugin that installs Headroom transport interception and exposes the retrieve tool.

## Install

```bash
npm install headroom-opencode
```

## Provider Config Helpers

Use these helpers when you need to generate OpenCode config that routes a `headroom` provider through a running Headroom proxy.

```ts
import {
  buildOpencodeConfigContent,
  createHeadroomProvider,
} from "headroom-opencode";

const provider = createHeadroomProvider({ proxyPort: 8787 });
const config = buildOpencodeConfigContent({
  proxyPort: 8787,
  defaultModel: "claude-sonnet-4-6",
});

console.log(provider.provider.headroom.npm);
console.log(config.model);
```

The generated provider uses `@ai-sdk/openai-compatible` and points model requests at `http://127.0.0.1:<port>/v1`.

## Native OpenCode Plugin

Use `HeadroomPlugin` when OpenCode should intercept provider traffic in-process and expose Headroom tooling from a plugin.

```ts
import { HeadroomPlugin } from "headroom-opencode";

export default async function plugin(input) {
  return HeadroomPlugin(input, {
    proxyUrl: process.env.HEADROOM_PROXY_URL ?? "http://127.0.0.1:8787",
  });
}
```

`HeadroomPlugin`:

- installs Headroom transport interception for OpenCode provider traffic.
- exposes the `headroom_retrieve` tool.
- publishes `HEADROOM_PROXY_URL` in the plugin output env.
- enforces optional native tool policies, with shell/HTTP transport checks as defense in depth.
- defaults to `http://127.0.0.1:8787` when no proxy URL is supplied.

### Tool policy enforcement

Pass `toolPolicy` to `HeadroomPlugin` (or set `HEADROOM_TOOL_POLICY_JSON`) to preflight outbound HTTP requests and child-process shell launches before they execute.

```ts
import { HeadroomPlugin } from "headroom-opencode";

export default async function plugin(input) {
  return HeadroomPlugin(input, {
    proxyUrl: "http://127.0.0.1:8787",
    toolPolicy: {
      version: 1,
      mode: "enforce",
      rules: [
        {
          id: "deny-direct-openai",
          scope: "http",
          action: "deny",
          domain: "api.openai.com",
          reason: "force egress through approved gateways",
        },
        {
          id: "approve-curl",
          scope: "shell",
          action: "require_approval",
          command: "curl",
        },
      ],
    },
  });
}
```

You can also keep the policy outside the plugin code:

```bash
export HEADROOM_TOOL_POLICY_PATH=~/.headroom/config/tool_policy.json
```

Or load it from an authenticated policy service:

```bash
export HEADROOM_TOOL_POLICY_URL=https://policy.example.com/v1/headroom
export HEADROOM_TOOL_POLICY_TOKEN="$POLICY_READ_TOKEN"
export HEADROOM_TOOL_POLICY_REFRESH_SECONDS=900
```

Or commit a repo-local policy file:

```text
<repo>/.headroom/tool_policy.json
```

```json
{
  "version": 1,
  "mode": "enforce",
  "defaultAction": "allow",
  "rules": [
    {
      "id": "deny-direct-openai",
      "scope": "http",
      "action": "deny",
      "domain": "api.openai.com",
      "reason": "force egress through approved gateways"
    },
    {
      "id": "ask-before-curl-post",
      "scope": "shell",
      "action": "require_approval",
      "command": "curl",
      "argsPattern": "\\b-X\\s+POST\\b"
    }
  ]
}
```

Behavior:

- scopes: `shell`, `http`, and cross-cutting `tool_call`
- actions: `allow`, `deny`, `require_approval`
- control precedence: explicit plugin policy → `HEADROOM_TOOL_POLICY_JSON` → `HEADROOM_TOOL_POLICY_PATH` → `HEADROOM_TOOL_POLICY_URL` → `~/.headroom/config/tool_policy.json` → nearest repo `.headroom/tool_policy.json`
- deterministic precedence: first matching rule wins
- matchers: `tool`, `command`, `argsPattern`, `cwdPattern`, `envKeys`, `domain`, `urlPattern`
- `report_only` mode logs the decision but allows the operation
- decisions are appended to `~/.headroom/tool_policy_audit.jsonl` and emitted as structured JSON lines on stderr
- native `tool.execute.before` enforcement covers shell and non-shell OpenCode tools; transport interception remains defense in depth
- remote policies use ETag revalidation and a credential-bound five-minute atomic cache; refresh can be extended to one hour
- an unavailable or invalid remote policy fails closed after the cache expires

`require_approval` currently fails closed in the OpenCode transport because there is no interactive approval callback yet.

Example audit line:

```json
{
  "event": "headroom_tool_policy_decision",
  "scope": "http",
  "action": "deny",
  "effective_action": "deny",
  "matched_rule": "deny-direct-openai",
  "resource": "https://api.openai.com/v1/responses"
}
```

## Retrieve Tool

```ts
import { createHeadroomRetrieveTool } from "headroom-opencode";

const retrieve = createHeadroomRetrieveTool({
  proxyBaseUrl: "http://127.0.0.1:8787",
});

const result = await retrieve.execute({
  hash: "0123456789abcdef01234567",
});
```

The tool calls `/v1/retrieve/<hash>` on the Headroom proxy.

## Compression Helper

```ts
import { compressWithHeadroom } from "headroom-opencode";

const result = await compressWithHeadroom(
  [{ role: "user", content: "Summarize this file" }],
  { model: "gpt-4o", proxyUrl: "http://127.0.0.1:8787" },
);

console.log(`Saved ${result.tokensSaved} tokens`);
```

## Models

| Model | Context | Output |
|---|---:|---:|
| `claude-sonnet-4-6` | 200K | 16K |
| `claude-opus-4-6` | 200K | 16K |
| `claude-haiku-4-5-20251001` | 200K | 8K |
| `gpt-4o` | 128K | 16K |
| `gpt-4.1` | 1M | 32K |

The provider config exposes these as `headroom/<model>` and defaults to `headroom/claude-sonnet-4-6`.

## Environment

| Variable | Used by | Description |
|---|---|---|
| `HEADROOM_PROXY_URL` | Native plugin | Proxy URL used by `HeadroomPlugin` |
| `OPENCODE_CONFIG_CONTENT` | OpenCode wrapper | Generated OpenCode provider, model, and MCP config |
| `HEADROOM_TOOL_POLICY_JSON` | Native plugin / child Node processes | Optional JSON policy document for native tool and transport checks |
| `HEADROOM_TOOL_POLICY_PATH` | Native plugin / child Node processes | Optional path to a shared JSON policy file; falls back to repo-local `.headroom/tool_policy.json` or `~/.headroom/config/tool_policy.json` when unset |
| `HEADROOM_TOOL_POLICY_URL` | Native plugin | HTTPS endpoint returning a versioned policy JSON document |
| `HEADROOM_TOOL_POLICY_TOKEN` | Native plugin | Optional bearer token for the remote policy service |
| `HEADROOM_TOOL_POLICY_REFRESH_SECONDS` | Native plugin | Cache refresh interval from 300 through 3600 seconds; invalid values use 300 |

## License

Apache-2.0
