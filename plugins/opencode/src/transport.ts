import { createRequire, syncBuiltinESMExports } from "node:module";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";

const nodeRequire = createRequire(import.meta.url);
const http = nodeRequire("node:http") as typeof import("node:http");
const https = nodeRequire("node:https") as typeof import("node:https");
const http2 = nodeRequire("node:http2") as typeof import("node:http2");
const childProcess = nodeRequire("node:child_process") as typeof import("node:child_process");
const fs = nodeRequire("node:fs") as typeof import("node:fs");

const BASE_URL_HEADER = "x-headroom-base-url";
const ORIGINAL_PATH_HEADER = "x-headroom-original-path";
const PROJECT_HEADER = "x-headroom-project";
const PROXY_ENV = "HEADROOM_OPENCODE_TRANSPORT_PROXY_URL";
export const TOOL_POLICY_ENV = "HEADROOM_TOOL_POLICY_JSON";
export const TOOL_POLICY_PATH_ENV = "HEADROOM_TOOL_POLICY_PATH";
const TOOL_POLICY_FILE_NAME = "tool_policy.json";
const STATE_KEY = Symbol.for("headroom.opencode.transport");

type FetchArgs = Parameters<typeof fetch>;
type HttpRequest = typeof http.request;
type HttpGet = typeof http.get;
type HttpsRequest = typeof https.request;
type HttpsGet = typeof https.get;
type Http2Connect = typeof http2.connect;
type ChildSpawn = typeof childProcess.spawn;
type ChildExec = typeof childProcess.exec;
type ChildExecFile = typeof childProcess.execFile;
type ChildFork = typeof childProcess.fork;
export type ToolPolicyAction = "allow" | "deny" | "require_approval";
export type ToolPolicyMode = "enforce" | "report_only";
export type ToolPolicyScope = "tool_call" | "shell" | "http";

export interface HeadroomToolPolicyRule {
  id?: string;
  scope: ToolPolicyScope;
  action: ToolPolicyAction;
  reason?: string;
  command?: string | string[];
  argsPattern?: string;
  cwdPattern?: string;
  envKeys?: string[];
  domain?: string | string[];
  urlPattern?: string;
}

export interface HeadroomToolPolicyConfig {
  mode?: ToolPolicyMode;
  defaultAction?: Extract<ToolPolicyAction, "allow" | "deny">;
  rules: HeadroomToolPolicyRule[];
}

type HeadroomToolPolicyInput = HeadroomToolPolicyConfig | string;

interface InstallOptions {
  proxyUrl: string;
  project?: string;
  debug?: boolean;
  toolPolicy?: HeadroomToolPolicyInput;
}

interface CompiledToolPolicyRule {
  id: string;
  scope: ToolPolicyScope;
  action: ToolPolicyAction;
  reason?: string;
  commands?: string[];
  argsPattern?: RegExp;
  cwdPattern?: RegExp;
  envKeys?: string[];
  domains?: string[];
  urlPattern?: RegExp;
}

interface CompiledToolPolicy {
  mode: ToolPolicyMode;
  defaultAction: "allow" | "deny";
  rules: CompiledToolPolicyRule[];
  serialized: string;
}

interface TransportState {
  refs: number;
  proxyUrl: string;
  project: string | undefined;
  debug: boolean;
  toolPolicy?: CompiledToolPolicy;
  previousNodeOptions?: string;
  previousProxyUrlEnv?: string;
  previousToolPolicyEnv?: string;
  originalFetch: typeof fetch;
  originalHttpRequest: HttpRequest;
  originalHttpGet: HttpGet;
  originalHttpsRequest: HttpsRequest;
  originalHttpsGet: HttpsGet;
  originalHttp2Connect: Http2Connect;
  originalChildSpawn: ChildSpawn;
  originalChildExec: ChildExec;
  originalChildExecFile: ChildExecFile;
  originalChildFork: ChildFork;
}

interface GlobalWithHeadroomTransport {
  [STATE_KEY]?: TransportState;
}

interface NodeRequestParts {
  url?: URL;
  options: Record<string, unknown>;
  callback?: (...args: unknown[]) => unknown;
}

interface PolicyDecisionBase {
  scope: "shell" | "http";
  action: ToolPolicyAction;
  effectiveAction: ToolPolicyAction;
  mode: ToolPolicyMode;
  matchedRuleId?: string;
  reason?: string;
  resource: string;
  requestHash: string;
}

interface ShellPolicyInput {
  scope: "shell";
  resource: string;
  command: string;
  argsText: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv | Record<string, unknown>;
}

interface HttpPolicyInput {
  scope: "http";
  resource: string;
  url: URL;
}

function getState(): TransportState | undefined {
  return (globalThis as GlobalWithHeadroomTransport)[STATE_KEY];
}

function setState(state: TransportState | undefined): void {
  (globalThis as GlobalWithHeadroomTransport)[STATE_KEY] = state;
}

// ponytail: the shim only exists next to the checkout build
// (plugins/opencode/dist/). The wheel ships entry.opencode.js alone, so
// `--import=<missing file>` killed every Node child at startup — including
// OpenCode's stdio MCP servers (issue #2798). No shim on disk, no injection:
// children go direct instead of dying. Upgrade path is bundling the shim into
// _dist/ so wheel installs get child-process routing back.
function shimImportSpecifier(): string | undefined {
  const shim = new URL("../hook-shim/handler.js", import.meta.url);
  return fs.existsSync(shim) ? shim.href : undefined;
}

function withNodeImportOption(existing: string | undefined, shim: string): string {
  const parts = existing?.trim() ? existing.trim().split(/\s+/) : [];
  const alreadyPresent = parts.some((part, index) => {
    return part === `--import=${shim}` || (part === "--import" && parts[index + 1] === shim);
  });
  if (!alreadyPresent) {
    parts.push(`--import=${shim}`);
  }
  return parts.join(" ");
}

function parseToolPolicyJson(raw: string, source: string): HeadroomToolPolicyConfig {
  try {
    const parsed = JSON.parse(raw) as HeadroomToolPolicyConfig;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("expected a JSON object");
    }
    return parsed;
  } catch (error) {
    throw new Error(`Invalid Headroom tool policy JSON in ${source}: ${String(error)}`);
  }
}

function readToolPolicyFile(filePath: string, source: string): HeadroomToolPolicyConfig {
  try {
    return parseToolPolicyJson(fs.readFileSync(filePath, "utf8"), source);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Invalid Headroom tool policy JSON")) {
      throw error;
    }
    throw new Error(`Invalid Headroom tool policy file ${filePath} (${source}): ${String(error)}`);
  }
}

function defaultGlobalToolPolicyPath(): string {
  const explicitConfigDir = process.env.HEADROOM_CONFIG_DIR?.trim();
  if (explicitConfigDir) {
    return path.join(explicitConfigDir, TOOL_POLICY_FILE_NAME);
  }
  const explicitWorkspaceDir = process.env.HEADROOM_WORKSPACE_DIR?.trim();
  if (explicitWorkspaceDir) {
    return path.join(explicitWorkspaceDir, "config", TOOL_POLICY_FILE_NAME);
  }
  return path.join(os.homedir(), ".headroom", "config", TOOL_POLICY_FILE_NAME);
}

function findLocalToolPolicyPath(project: string | undefined): string | undefined {
  const start = path.resolve(project || process.cwd());
  let current = start;
  while (true) {
    const candidate = path.join(current, ".headroom", TOOL_POLICY_FILE_NAME);
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

function loadToolPolicyConfig(
  policy: HeadroomToolPolicyInput | undefined,
  project: string | undefined,
): HeadroomToolPolicyConfig | undefined {
  if (policy === undefined) {
    const raw = process.env[TOOL_POLICY_ENV]?.trim();
    if (raw) {
      return parseToolPolicyJson(raw, TOOL_POLICY_ENV);
    }
    const rawPath = process.env[TOOL_POLICY_PATH_ENV]?.trim();
    if (rawPath) {
      return readToolPolicyFile(rawPath, TOOL_POLICY_PATH_ENV);
    }
    const localPath = findLocalToolPolicyPath(project);
    if (localPath) {
      return readToolPolicyFile(localPath, localPath);
    }
    const globalPath = defaultGlobalToolPolicyPath();
    if (fs.existsSync(globalPath)) {
      return readToolPolicyFile(globalPath, globalPath);
    }
    return undefined;
  }
  if (typeof policy !== "string") {
    return policy;
  }
  const trimmed = policy.trim();
  if (!trimmed) {
    return undefined;
  }
  if (trimmed.startsWith("{")) {
    return parseToolPolicyJson(trimmed, "inline string");
  }
  return readToolPolicyFile(trimmed, trimmed);
}

function compileRegex(source: string | undefined, field: string, ruleId: string): RegExp | undefined {
  if (!source) {
    return undefined;
  }
  try {
    return new RegExp(source);
  } catch (error) {
    throw new Error(
      `Invalid Headroom tool policy regex for ${field} in rule ${ruleId}: ${String(error)}`,
    );
  }
}

function asArray(value: string | string[] | undefined): string[] | undefined {
  if (value === undefined) {
    return undefined;
  }
  return Array.isArray(value) ? value : [value];
}

function compileToolPolicy(
  policy: HeadroomToolPolicyInput | undefined,
  project: string | undefined,
): CompiledToolPolicy | undefined {
  const loaded = loadToolPolicyConfig(policy, project);
  if (!loaded) {
    return undefined;
  }
  if (!Array.isArray(loaded.rules)) {
    throw new Error("Headroom tool policy requires a rules array");
  }
  const compiledRules = loaded.rules.map((rule, index): CompiledToolPolicyRule => {
    const id = rule.id?.trim() || `rule_${index + 1}`;
    if (rule.scope !== "tool_call" && rule.scope !== "shell" && rule.scope !== "http") {
      throw new Error(`Invalid Headroom tool policy scope in rule ${id}: ${String(rule.scope)}`);
    }
    if (rule.action !== "allow" && rule.action !== "deny" && rule.action !== "require_approval") {
      throw new Error(`Invalid Headroom tool policy action in rule ${id}: ${String(rule.action)}`);
    }
    return {
      id,
      scope: rule.scope,
      action: rule.action,
      reason: rule.reason,
      commands: asArray(rule.command)?.map((entry) => entry.toLowerCase()),
      argsPattern: compileRegex(rule.argsPattern, "argsPattern", id),
      cwdPattern: compileRegex(rule.cwdPattern, "cwdPattern", id),
      envKeys: rule.envKeys?.map((entry) => entry.toLowerCase()),
      domains: asArray(rule.domain)?.map((entry) => entry.toLowerCase()),
      urlPattern: compileRegex(rule.urlPattern, "urlPattern", id),
    };
  });
  const defaultAction = loaded.defaultAction ?? "allow";
  if (defaultAction !== "allow" && defaultAction !== "deny") {
    throw new Error(`Invalid Headroom tool policy defaultAction: ${String(defaultAction)}`);
  }
  const mode = loaded.mode ?? "enforce";
  if (mode !== "enforce" && mode !== "report_only") {
    throw new Error(`Invalid Headroom tool policy mode: ${String(mode)}`);
  }
  return {
    mode,
    defaultAction,
    rules: compiledRules,
    serialized: JSON.stringify({
      mode,
      defaultAction,
      rules: loaded.rules.map((rule, index) => ({
        ...rule,
        id: rule.id?.trim() || `rule_${index + 1}`,
      })),
    }),
  };
}

function withShimEnv(
  env: NodeJS.ProcessEnv | Record<string, unknown> | undefined,
  proxyUrl: string,
  toolPolicy: CompiledToolPolicy | undefined,
): NodeJS.ProcessEnv {
  const nextEnv = { ...(env ?? process.env) } as NodeJS.ProcessEnv;
  nextEnv[PROXY_ENV] = proxyUrl;
  if (toolPolicy) {
    nextEnv[TOOL_POLICY_ENV] = toolPolicy.serialized;
  } else {
    delete nextEnv[TOOL_POLICY_ENV];
  }
  const shim = shimImportSpecifier();
  if (shim) {
    nextEnv.NODE_OPTIONS = withNodeImportOption(nextEnv.NODE_OPTIONS, shim);
  }
  return nextEnv;
}

function installProcessEnv(proxyUrl: string, toolPolicy: CompiledToolPolicy | undefined): void {
  process.env[PROXY_ENV] = proxyUrl;
  if (toolPolicy) {
    process.env[TOOL_POLICY_ENV] = toolPolicy.serialized;
  } else {
    delete process.env[TOOL_POLICY_ENV];
  }
  const shim = shimImportSpecifier();
  if (shim) {
    process.env.NODE_OPTIONS = withNodeImportOption(process.env.NODE_OPTIONS, shim);
  }
}

function isOptions(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && !(value instanceof URL);
}

function injectOptionsEnv(args: unknown[], optionIndex: number, proxyUrl: string): unknown[] {
  const state = getState();
  const nextArgs = [...args];
  const callback = typeof nextArgs.at(-1) === "function" ? nextArgs.pop() : undefined;
  const existing = isOptions(nextArgs[optionIndex]) ? { ...(nextArgs[optionIndex] as Record<string, unknown>) } : {};
  existing.env = withShimEnv(existing.env as NodeJS.ProcessEnv | undefined, proxyUrl, state?.toolPolicy);

  if (isOptions(nextArgs[optionIndex])) {
    nextArgs[optionIndex] = existing;
  } else {
    nextArgs.splice(optionIndex, 0, existing);
  }

  if (callback) {
    nextArgs.push(callback);
  }
  return nextArgs;
}

function normalizedCommandName(command: string): string {
  const trimmed = command.trim();
  if (!trimmed) {
    return "";
  }
  return path.basename(trimmed).toLowerCase();
}

function commandMatches(command: string, patterns: string[] | undefined): boolean {
  if (!patterns?.length) {
    return true;
  }
  const normalized = normalizedCommandName(command);
  const lowered = command.trim().toLowerCase();
  return patterns.some((pattern) => {
    const candidate = pattern.toLowerCase();
    return candidate === lowered || candidate === normalized || path.basename(candidate) === normalized;
  });
}

function shellCommandBinary(commandLine: string): string {
  const trimmed = commandLine.trim();
  if (!trimmed) {
    return "";
  }
  const quoted = trimmed.match(/^(["'])([^"']+)\1/);
  if (quoted?.[2]) {
    return quoted[2];
  }
  return trimmed.split(/\s+/, 1)[0] ?? "";
}

function matchesDomain(hostname: string, patterns: string[] | undefined): boolean {
  if (!patterns?.length) {
    return true;
  }
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return patterns.some((pattern) => {
    const candidate = pattern.toLowerCase();
    if (candidate.startsWith("*.")) {
      const suffix = candidate.slice(2);
      return normalized === suffix || normalized.endsWith(`.${suffix}`);
    }
    return normalized === candidate;
  });
}

function hashPolicyResource(resource: string): string {
  return createHash("sha256").update(resource).digest("hex").slice(0, 16);
}

function emitPolicyDecision(decision: PolicyDecisionBase): void {
  try {
    process.stderr.write(
      `${JSON.stringify({
        event: "headroom_tool_policy_decision",
        timestamp: new Date().toISOString(),
        scope: decision.scope,
        action: decision.action,
        effective_action: decision.effectiveAction,
        mode: decision.mode,
        matched_rule: decision.matchedRuleId ?? "",
        reason: decision.reason ?? "",
        request_hash: decision.requestHash,
        resource: decision.resource,
      })}\n`,
    );
  } catch {
    // Never let logging break the transport.
  }
}

function evaluatePolicy(
  policy: CompiledToolPolicy | undefined,
  input: ShellPolicyInput | HttpPolicyInput,
): PolicyDecisionBase | undefined {
  if (!policy) {
    return undefined;
  }
  const matchedRule = policy.rules.find((rule) => {
    if (rule.scope !== "tool_call" && rule.scope !== input.scope) {
      return false;
    }
    if (input.scope === "shell") {
      if (!commandMatches(input.command, rule.commands)) {
        return false;
      }
      if (rule.argsPattern && !rule.argsPattern.test(input.argsText)) {
        return false;
      }
      if (rule.cwdPattern && !rule.cwdPattern.test(input.cwd ?? "")) {
        return false;
      }
      if (
        rule.envKeys?.length &&
        !rule.envKeys.every((entry) =>
          Object.keys(input.env ?? process.env).some((key) => key.toLowerCase() === entry),
        )
      ) {
        return false;
      }
      return true;
    }
    if (!matchesDomain(input.url.hostname, rule.domains)) {
      return false;
    }
    if (rule.urlPattern && !rule.urlPattern.test(input.url.href)) {
      return false;
    }
    return true;
  });
  const action = matchedRule?.action ?? policy.defaultAction;
  const effectiveAction = policy.mode === "report_only" && action !== "allow" ? "allow" : action;
  return {
    scope: input.scope,
    action,
    effectiveAction,
    mode: policy.mode,
    matchedRuleId: matchedRule?.id,
    reason: matchedRule?.reason,
    resource: input.resource,
    requestHash: hashPolicyResource(input.resource),
  };
}

function enforcePolicy(
  policy: CompiledToolPolicy | undefined,
  input: ShellPolicyInput | HttpPolicyInput,
): void {
  const decision = evaluatePolicy(policy, input);
  if (!decision) {
    return;
  }
  emitPolicyDecision(decision);
  if (decision.effectiveAction === "allow") {
    return;
  }
  if (decision.effectiveAction === "require_approval") {
    throw new Error(
      `[headroom] Tool policy requires approval for ${input.scope} target ${input.resource}` +
        (decision.matchedRuleId ? ` (rule=${decision.matchedRuleId})` : "") +
        ". No approval handler is installed in the OpenCode transport yet.",
    );
  }
  throw new Error(
    `[headroom] Tool policy denied ${input.scope} target ${input.resource}` +
      (decision.matchedRuleId ? ` (rule=${decision.matchedRuleId})` : "") +
      (decision.reason ? `: ${decision.reason}` : ""),
  );
}

function wrapSpawn(originalSpawn: ChildSpawn): ChildSpawn {
  return function headroomSpawn(this: unknown, ...args: unknown[]) {
    const state = getState();
    if (!state) {
      return Reflect.apply(originalSpawn, this, args);
    }
    const command = String(args[0] ?? "");
    const commandArgs = Array.isArray(args[1]) ? args[1].map((entry) => String(entry)) : [];
    const options = isOptions(args[Array.isArray(args[1]) ? 2 : 1])
      ? (args[Array.isArray(args[1]) ? 2 : 1] as Record<string, unknown>)
      : undefined;
    enforcePolicy(state.toolPolicy, {
      scope: "shell",
      resource: [command, ...commandArgs].join(" ").trim() || command,
      command,
      argsText: commandArgs.join(" "),
      cwd: typeof options?.cwd === "string" ? options.cwd : undefined,
      env: options?.env as NodeJS.ProcessEnv | Record<string, unknown> | undefined,
    });
    const optionIndex = Array.isArray(args[1]) ? 2 : 1;
    return Reflect.apply(originalSpawn, this, injectOptionsEnv(args, optionIndex, state.proxyUrl));
  } as ChildSpawn;
}

function wrapExec(originalExec: ChildExec): ChildExec {
  return function headroomExec(this: unknown, ...args: unknown[]) {
    const state = getState();
    if (!state) {
      return Reflect.apply(originalExec, this, args);
    }
    const commandLine = String(args[0] ?? "");
    const options = isOptions(args[1]) ? (args[1] as Record<string, unknown>) : undefined;
    enforcePolicy(state.toolPolicy, {
      scope: "shell",
      resource: commandLine,
      command: shellCommandBinary(commandLine),
      argsText: commandLine,
      cwd: typeof options?.cwd === "string" ? options.cwd : undefined,
      env: options?.env as NodeJS.ProcessEnv | Record<string, unknown> | undefined,
    });
    return Reflect.apply(originalExec, this, injectOptionsEnv(args, 1, state.proxyUrl));
  } as ChildExec;
}

function wrapExecFile(originalExecFile: ChildExecFile): ChildExecFile {
  return function headroomExecFile(this: unknown, ...args: unknown[]) {
    const state = getState();
    if (!state) {
      return Reflect.apply(originalExecFile, this, args);
    }
    const command = String(args[0] ?? "");
    const commandArgs = Array.isArray(args[1]) ? args[1].map((entry) => String(entry)) : [];
    const options = isOptions(args[Array.isArray(args[1]) ? 2 : 1])
      ? (args[Array.isArray(args[1]) ? 2 : 1] as Record<string, unknown>)
      : undefined;
    enforcePolicy(state.toolPolicy, {
      scope: "shell",
      resource: [command, ...commandArgs].join(" ").trim() || command,
      command,
      argsText: commandArgs.join(" "),
      cwd: typeof options?.cwd === "string" ? options.cwd : undefined,
      env: options?.env as NodeJS.ProcessEnv | Record<string, unknown> | undefined,
    });
    const optionIndex = Array.isArray(args[1]) ? 2 : 1;
    return Reflect.apply(originalExecFile, this, injectOptionsEnv(args, optionIndex, state.proxyUrl));
  } as ChildExecFile;
}

function wrapFork(originalFork: ChildFork): ChildFork {
  return function headroomFork(this: unknown, ...args: unknown[]) {
    const state = getState();
    if (!state) {
      return Reflect.apply(originalFork, this, args);
    }
    const command = String(args[0] ?? "");
    const commandArgs = Array.isArray(args[1]) ? args[1].map((entry) => String(entry)) : [];
    const options = isOptions(args[Array.isArray(args[1]) ? 2 : 1])
      ? (args[Array.isArray(args[1]) ? 2 : 1] as Record<string, unknown>)
      : undefined;
    enforcePolicy(state.toolPolicy, {
      scope: "shell",
      resource: [command, ...commandArgs].join(" ").trim() || command,
      command,
      argsText: commandArgs.join(" "),
      cwd: typeof options?.cwd === "string" ? options.cwd : undefined,
      env: options?.env as NodeJS.ProcessEnv | Record<string, unknown> | undefined,
    });
    const optionIndex = Array.isArray(args[1]) ? 2 : 1;
    return Reflect.apply(originalFork, this, injectOptionsEnv(args, optionIndex, state.proxyUrl));
  } as ChildFork;
}

function normalizeProxyUrl(proxyUrl: string): URL {
  return new URL(proxyUrl);
}

function isLoopback(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

function shouldRoute(url: URL, proxy: URL): boolean {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return false;
  }
  if (isLoopback(url.hostname)) {
    return false;
  }
  if (url.origin === proxy.origin) {
    return false;
  }
  return true;
}

function routedUrl(upstream: URL, proxy: URL): URL {
  return new URL(`${upstream.pathname}${upstream.search}`, proxy.origin);
}

function normalizedOpenAiProxyPath(pathname: string): string | undefined {
  if (pathname.endsWith("/chat/completions")) {
    return "/v1/chat/completions";
  }
  if (pathname.endsWith("/responses")) {
    return "/v1/responses";
  }
  return undefined;
}

function routedUrlForOpenCode(upstream: URL, proxy: URL): { url: URL; originalPath: string | undefined } {
  const normalizedPath = normalizedOpenAiProxyPath(upstream.pathname);
  if (!normalizedPath) {
    return {
      url: routedUrl(upstream, proxy),
      originalPath: undefined,
    };
  }

  return {
    url: new URL(`${normalizedPath}${upstream.search}`, proxy.origin),
    originalPath: upstream.pathname,
  };
}

function requestUrl(input: RequestInfo | URL): URL {
  if (input instanceof Request) {
    return new URL(input.url);
  }
  if (input instanceof URL) {
    return input;
  }
  return new URL(String(input));
}

function mergeFetchHeaders(
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  upstream: URL | undefined,
  originalPath: string | undefined = undefined,
  project: string | undefined = undefined,
): Headers {
  const headers = new Headers(input instanceof Request ? input.headers : undefined);
  if (init?.headers) {
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
  }
  if (upstream) {
    headers.set(BASE_URL_HEADER, upstream.origin);
    headers.delete("host");
  }
  if (originalPath) {
    headers.set(ORIGINAL_PATH_HEADER, originalPath);
  }
  if (project) {
    headers.set(PROJECT_HEADER, project);
  }
  return headers;
}

function withRoutedFetchInput(input: RequestInfo | URL, init: RequestInit | undefined, proxy: URL, project: string | undefined): FetchArgs {
  const upstream = requestUrl(input);
  if (!shouldRoute(upstream, proxy)) {
    return [input, init];
  }

  const { url: nextUrl, originalPath } = routedUrlForOpenCode(upstream, proxy);
  const nextInit = {
    ...init,
    headers: mergeFetchHeaders(input, init, upstream, originalPath, project),
  };

  if (input instanceof Request) {
    return [new Request(nextUrl, input), nextInit];
  }
  return [nextUrl, nextInit];
}

function splitNodeArgs(args: unknown[]): NodeRequestParts {
  const callback = typeof args.at(-1) === "function" ? (args.at(-1) as (...args: unknown[]) => unknown) : undefined;
  const withoutCallback = callback ? args.slice(0, -1) : args;
  const [first, second] = withoutCallback;
  const options = typeof second === "object" && second !== null ? { ...(second as Record<string, unknown>) } : {};

  if (first instanceof URL) {
    return { url: first, options, callback };
  }
  if (typeof first === "string") {
    try {
      return { url: new URL(first), options, callback };
    } catch {
      return { options, callback };
    }
  }
  if (typeof first === "object" && first !== null) {
    const requestOptions = { ...(first as Record<string, unknown>), ...options };
    return { url: urlFromRequestOptions(requestOptions), options: requestOptions, callback };
  }
  return { options, callback };
}

function urlFromRequestOptions(options: Record<string, unknown>): URL | undefined {
  const protocol = String(options.protocol ?? "http:");
  if (protocol !== "http:" && protocol !== "https:") {
    return undefined;
  }

  const hostValue = options.hostname ?? options.host;
  if (!hostValue) {
    return undefined;
  }

  const hostname = String(hostValue).replace(/:\d+$/, "");
  const port = options.port ? `:${String(options.port)}` : "";
  const path = String(options.path ?? "/");
  try {
    return new URL(`${protocol}//${hostname}${port}${path}`);
  } catch {
    return undefined;
  }
}

function headersForNodeRequest(
  options: Record<string, unknown>,
  upstream: URL,
  originalPath: string | undefined,
  project: string | undefined,
): Record<string, string> {
  const headers = new Headers(options.headers as HeadersInit | undefined);
  headers.set(BASE_URL_HEADER, upstream.origin);
  if (originalPath) {
    headers.set(ORIGINAL_PATH_HEADER, originalPath);
  }
  if (project) {
    headers.set(PROJECT_HEADER, project);
  }
  headers.delete("host");

  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function routedNodeOptions(parts: NodeRequestParts, proxy: URL, project: string | undefined): Record<string, unknown> | undefined {
  if (!parts.url || !shouldRoute(parts.url, proxy)) {
    return undefined;
  }

  const { url: nextUrl, originalPath } = routedUrlForOpenCode(parts.url, proxy);
  const {
    agent: _agent,
    auth: _auth,
    createConnection: _createConnection,
    defaultPort: _defaultPort,
    family: _family,
    headers: _headers,
    host: _host,
    hostname: _hostname,
    href: _href,
    lookup: _lookup,
    path: _path,
    pathname: _pathname,
    port: _port,
    protocol: _protocol,
    search: _search,
    servername: _servername,
    setHost: _setHost,
    ...rest
  } = parts.options;

  return {
    ...rest,
    protocol: nextUrl.protocol,
    hostname: nextUrl.hostname,
    port: nextUrl.port || undefined,
    path: `${nextUrl.pathname}${nextUrl.search}`,
    headers: headersForNodeRequest(parts.options, parts.url, originalPath, project),
  };
}

function wrapRequest(
  originalHttpRequest: HttpRequest,
  originalHttpsRequest: HttpsRequest,
  originalRequest: HttpRequest | HttpsRequest,
): HttpRequest | HttpsRequest {
  return function headroomRequest(this: unknown, ...args: unknown[]) {
    const state = getState();
    if (!state) {
      return Reflect.apply(originalRequest, this, args);
    }

    const proxy = normalizeProxyUrl(state.proxyUrl);
    const parts = splitNodeArgs(args);
    if (parts.url) {
      enforcePolicy(state.toolPolicy, {
        scope: "http",
        resource: parts.url.href,
        url: parts.url,
      });
    }
    const nextOptions = routedNodeOptions(parts, proxy, state.project);
    if (!nextOptions) {
      return Reflect.apply(originalRequest, this, args);
    }

    const targetRequest = proxy.protocol === "https:" ? originalHttpsRequest : originalHttpRequest;
    const nextArgs = parts.callback ? [nextOptions, parts.callback] : [nextOptions];
    return Reflect.apply(targetRequest, this, nextArgs);
  } as HttpRequest | HttpsRequest;
}

function wrapGet(request: HttpRequest | HttpsRequest): HttpGet | HttpsGet {
  return function headroomGet(this: unknown, ...args: unknown[]) {
    const req = Reflect.apply(request, this, args);
    req.end();
    return req;
  } as HttpGet | HttpsGet;
}

function wrapHttp2Connect(originalConnect: Http2Connect): Http2Connect {
  return function headroomHttp2Connect(this: unknown, authority: string | URL, ...args: unknown[]) {
    const state = getState();
    if (state) {
      const proxy = normalizeProxyUrl(state.proxyUrl);
      const upstream = authority instanceof URL ? authority : new URL(String(authority));
      enforcePolicy(state.toolPolicy, {
        scope: "http",
        resource: upstream.href,
        url: upstream,
      });
      if (shouldRoute(upstream, proxy)) {
        throw new Error(
          `Headroom OpenCode wrap blocked direct HTTP/2 connection to ${upstream.origin}. ` +
            "Use fetch, http, or https so traffic can be routed through Headroom.",
        );
      }
    }
    return Reflect.apply(originalConnect, this, [authority, ...args]);
  } as Http2Connect;
}

export function installHeadroomTransport(options: InstallOptions): () => void {
  const existing = getState();
  const toolPolicy = compileToolPolicy(options.toolPolicy, options.project);
  if (existing) {
    existing.refs += 1;
    existing.proxyUrl = options.proxyUrl;
    existing.project = options.project;
    existing.debug = Boolean(options.debug);
    existing.toolPolicy = toolPolicy;
    installProcessEnv(options.proxyUrl, toolPolicy);
    return () => uninstallHeadroomTransport();
  }

  const state: TransportState = {
    refs: 1,
    proxyUrl: options.proxyUrl,
    project: options.project,
    debug: Boolean(options.debug),
    toolPolicy,
    previousNodeOptions: process.env.NODE_OPTIONS,
    previousProxyUrlEnv: process.env[PROXY_ENV],
    previousToolPolicyEnv: process.env[TOOL_POLICY_ENV],
    originalFetch: globalThis.fetch,
    originalHttpRequest: http.request,
    originalHttpGet: http.get,
    originalHttpsRequest: https.request,
    originalHttpsGet: https.get,
    originalHttp2Connect: http2.connect,
    originalChildSpawn: childProcess.spawn,
    originalChildExec: childProcess.exec,
    originalChildExecFile: childProcess.execFile,
    originalChildFork: childProcess.fork,
  };

  setState(state);
  installProcessEnv(options.proxyUrl, toolPolicy);
  globalThis.fetch = async (...args: FetchArgs) => {
    const current = getState();
    if (!current) {
      return state.originalFetch(...args);
    }
    const upstream = requestUrl(args[0]);
    enforcePolicy(current.toolPolicy, {
      scope: "http",
      resource: upstream.href,
      url: upstream,
    });
    const proxy = normalizeProxyUrl(current.proxyUrl);
    const [nextInput, nextInit] = withRoutedFetchInput(args[0], args[1], proxy, current.project);
    return state.originalFetch(nextInput, nextInit);
  };

  http.request = wrapRequest(state.originalHttpRequest, state.originalHttpsRequest, state.originalHttpRequest) as HttpRequest;
  https.request = wrapRequest(state.originalHttpRequest, state.originalHttpsRequest, state.originalHttpsRequest) as HttpsRequest;
  http.get = wrapGet(http.request) as HttpGet;
  https.get = wrapGet(https.request) as HttpsGet;
  http2.connect = wrapHttp2Connect(state.originalHttp2Connect);
  childProcess.spawn = wrapSpawn(state.originalChildSpawn);
  childProcess.exec = wrapExec(state.originalChildExec);
  childProcess.execFile = wrapExecFile(state.originalChildExecFile);
  childProcess.fork = wrapFork(state.originalChildFork);
  syncBuiltinESMExports();

  return () => uninstallHeadroomTransport();
}

export function uninstallHeadroomTransport(): void {
  const state = getState();
  if (!state) {
    return;
  }

  state.refs -= 1;
  if (state.refs > 0) {
    return;
  }

  globalThis.fetch = state.originalFetch;
  http.request = state.originalHttpRequest;
  http.get = state.originalHttpGet;
  https.request = state.originalHttpsRequest;
  https.get = state.originalHttpsGet;
  http2.connect = state.originalHttp2Connect;
  childProcess.spawn = state.originalChildSpawn;
  childProcess.exec = state.originalChildExec;
  childProcess.execFile = state.originalChildExecFile;
  childProcess.fork = state.originalChildFork;
  syncBuiltinESMExports();
  if (state.previousNodeOptions === undefined) {
    delete process.env.NODE_OPTIONS;
  } else {
    process.env.NODE_OPTIONS = state.previousNodeOptions;
  }
  if (state.previousProxyUrlEnv === undefined) {
    delete process.env[PROXY_ENV];
  } else {
    process.env[PROXY_ENV] = state.previousProxyUrlEnv;
  }
  if (state.previousToolPolicyEnv === undefined) {
    delete process.env[TOOL_POLICY_ENV];
  } else {
    process.env[TOOL_POLICY_ENV] = state.previousToolPolicyEnv;
  }
  setState(undefined);
}
