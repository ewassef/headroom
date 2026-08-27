import type { Plugin } from "@opencode-ai/plugin";
import { tool } from "@opencode-ai/plugin";
import { z } from "zod";

import { createHeadroomRetrieveTool, getDefaultProxyUrl } from "./retrieve.js";
import type { HeadroomToolPolicyConfig } from "./transport.js";
import {
  enforceNativeToolExecution,
  installHeadroomTransport,
  refreshHeadroomToolPolicy,
  TOOL_POLICY_ENV,
  TOOL_POLICY_PATH_ENV,
  TOOL_POLICY_REFRESH_SECONDS_ENV,
  TOOL_POLICY_TOKEN_ENV,
  TOOL_POLICY_URL_ENV,
} from "./transport.js";

export interface HeadroomOpenCodePluginOptions {
  proxyUrl?: string;
  project?: string;
  backend?: string;
  debug?: boolean;
  toolPolicy?: HeadroomToolPolicyConfig | string;
}

function normalizeProxyUrl(url: string): string {
  return url.replace(/\/+$/, "");
}

function resolveProxyUrl(options?: HeadroomOpenCodePluginOptions): string {
  return normalizeProxyUrl(
    options?.proxyUrl ??
      process.env.HEADROOM_PROXY_URL ??
      process.env.HEADROOM_BASE_URL ??
      getDefaultProxyUrl(),
  );
}

export const HeadroomPlugin: Plugin = async (input, options = {}) => {
  const pluginOptions = options as HeadroomOpenCodePluginOptions;
  const proxyUrl = resolveProxyUrl(pluginOptions);
  const projectPath = input.worktree || input.directory;
  const project = pluginOptions.project ?? projectPath;
  const retrieveTool = createHeadroomRetrieveTool({ proxyBaseUrl: proxyUrl });
  const uninstallTransport = installHeadroomTransport({
    proxyUrl,
    project,
    policyProject: projectPath,
    debug: pluginOptions.debug,
    toolPolicy: pluginOptions.toolPolicy,
  });
  await refreshHeadroomToolPolicy();

  return {
    dispose: async () => {
      uninstallTransport();
    },
    tool: {
      headroom_retrieve: tool({
        description: retrieveTool.description,
        args: {
          hash: z
            .string()
            .regex(/^[a-f0-9]{24}$/i, "Expected 24-character hex hash"),
        },
        async execute(args) {
          return retrieveTool.execute(args);
        },
      }),
    },
    "shell.env": async (_input, output) => {
      delete output.env[TOOL_POLICY_TOKEN_ENV];
      output.env.HEADROOM_ACTIVE = "1";
      output.env.HEADROOM_PROXY_URL = proxyUrl;
      output.env.HEADROOM_PROJECT = project;
      if (pluginOptions.backend) {
        output.env.HEADROOM_BACKEND = pluginOptions.backend;
      }
      if (process.env[TOOL_POLICY_ENV]) {
        output.env[TOOL_POLICY_ENV] = process.env[TOOL_POLICY_ENV];
      }
      if (process.env[TOOL_POLICY_PATH_ENV]) {
        output.env[TOOL_POLICY_PATH_ENV] = process.env[TOOL_POLICY_PATH_ENV];
      }
      for (const name of [
        TOOL_POLICY_URL_ENV,
        TOOL_POLICY_REFRESH_SECONDS_ENV,
      ]) {
        if (process.env[name]) {
          output.env[name] = process.env[name];
        }
      }
    },
    "tool.execute.before": async (hookInput, output) => {
      await enforceNativeToolExecution(hookInput.tool, output.args, projectPath);
    },
  };
};

export default HeadroomPlugin;
