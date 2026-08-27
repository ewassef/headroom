import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { HeadroomPlugin } from "./plugin.js";

function pluginInput() {
  return {
    client: {},
    project: { id: "project-1" },
    directory: "/repo",
    worktree: "/repo",
    experimental_workspace: {
      register: vi.fn(),
    },
    $: {},
  } as never;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("HeadroomPlugin", () => {
  it("adds only Headroom metadata to shell env", async () => {
    const plugin = await HeadroomPlugin(pluginInput(), {
      proxyUrl: "http://127.0.0.1:8787/",
      backend: "litellm",
      toolPolicy: {
        rules: [{ id: "deny-curl", scope: "shell", action: "deny", command: "curl" }],
      },
    });
    const output = {
      env: {
        OPENAI_BASE_URL: "https://deepseek.example/v1",
        ANTHROPIC_BASE_URL: "https://anthropic.example",
      },
    };

    await plugin["shell.env"]?.({ cwd: "/repo" }, output);

    expect(output.env).toMatchObject({
      HEADROOM_ACTIVE: "1",
      HEADROOM_PROXY_URL: "http://127.0.0.1:8787",
      HEADROOM_PROJECT: "/repo",
      HEADROOM_BACKEND: "litellm",
      HEADROOM_TOOL_POLICY_JSON: JSON.stringify({
        version: 1,
        mode: "enforce",
        defaultAction: "allow",
        rules: [{ id: "deny-curl", scope: "shell", action: "deny", command: "curl" }],
      }),
      OPENAI_BASE_URL: "https://deepseek.example/v1",
      ANTHROPIC_BASE_URL: "https://anthropic.example",
    });
    expect(output.env).not.toHaveProperty("HEADROOM_OPENCODE_TOOL_POLICY_JSON");
    await plugin.dispose?.();
  });

  it("never exposes the remote policy bearer token to shell commands", async () => {
    const previousToken = process.env.HEADROOM_TOOL_POLICY_TOKEN;
    process.env.HEADROOM_TOOL_POLICY_TOKEN = "private-policy-token";
    try {
      const plugin = await HeadroomPlugin(pluginInput(), {
        proxyUrl: "http://127.0.0.1:8787",
        toolPolicy: { rules: [] },
      });
      const output = {
        env: { HEADROOM_TOOL_POLICY_TOKEN: "inherited-token" } as Record<string, string>,
      };

      await plugin["shell.env"]?.({ cwd: "/repo" }, output);

      expect(output.env).not.toHaveProperty("HEADROOM_TOOL_POLICY_TOKEN");
      await plugin.dispose?.();
    } finally {
      if (previousToken === undefined) delete process.env.HEADROOM_TOOL_POLICY_TOKEN;
      else process.env.HEADROOM_TOOL_POLICY_TOKEN = previousToken;
    }
  });

  it("blocks native shell tools using the filesystem project directory", async () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "headroom-native-policy-"));
    fs.mkdirSync(path.join(repo, ".headroom"));
    fs.writeFileSync(
      path.join(repo, ".headroom", "tool_policy.json"),
      JSON.stringify({
        rules: [{ id: "deny-wrapped", scope: "shell", action: "deny", command: "curl" }],
      }),
    );
    const input = pluginInput() as unknown as { directory: string; worktree: string };
    input.directory = repo;
    input.worktree = "";
    try {
      const plugin = await HeadroomPlugin(input as never, {
        proxyUrl: "http://127.0.0.1:8787",
      });
      await expect(
        plugin["tool.execute.before"]?.(
          { tool: "bash", sessionID: "s", callID: "c" },
          { args: { command: "echo ok && sudo env X=1 curl example.test" } },
        ),
      ).rejects.toThrow(/deny-wrapped/);
      await plugin.dispose?.();
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

  it("blocks a non-shell native tool by tool name", async () => {
    const plugin = await HeadroomPlugin(pluginInput(), {
      proxyUrl: "http://127.0.0.1:8787",
      toolPolicy: {
        rules: [
          {
            id: "deny-write",
            scope: "tool_call",
            action: "deny",
            tool: "write",
            argsPattern: '"path":"secret\\.txt"',
          },
        ],
      },
    });

    await expect(
      plugin["tool.execute.before"]?.(
        { tool: "write", sessionID: "s", callID: "c" },
        { args: { value: "data", path: "secret.txt" } },
      ),
    ).rejects.toThrow(/deny-write/);
    await plugin.dispose?.();
  });

  it("exposes a headroom_retrieve tool backed by the proxy", async () => {
    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => "original content",
    }));
    vi.stubGlobal("fetch", fetchMock);

    const plugin = await HeadroomPlugin(pluginInput(), {
      proxyUrl: "http://127.0.0.1:8787",
    });
    const result = await plugin.tool?.headroom_retrieve.execute(
      { hash: "0123456789abcdef01234567" },
      {} as never,
    );

    expect(result).toBe("original content");
    expect(fetchMock).toHaveBeenCalledWith(
      "http://127.0.0.1:8787/v1/retrieve/0123456789abcdef01234567",
      expect.any(Object),
    );
  });
});
