import { spawn, spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  lstatSync,
  realpathSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, relative, resolve } from "node:path";

const FILE_TOOLS: Record<string, true> = {
  read: true,
  edit: true,
  write: true,
  grep: true,
  glob: true,
};
const ALLOWED_TOOLS: Record<string, true> = {
  ...FILE_TOOLS,
  bash: true,
  todo: true,
  broker_finalize: true,
};
const RESEARCH_CALLER = "backlog-maturation-research";
const REVIEW_CALLER = "review-agent";
const RESEARCH_AGENTS: Record<string, "sonnet" | "fable"> = {
  "backlog-researcher": "sonnet",
  "backlog-vision": "sonnet",
  "backlog-researcher-max": "fable",
};
const RESEARCH_MAX_TASKS = 5;
const RESEARCH_MAX_SONNET = 4;
const RESEARCH_MAX_FABLE = 1;
const RESEARCH_SPAWN_CONTROLS: Record<string, true> = {
  model: true,
  async: true,
  background: true,
  isolated: true,
  isolation: true,
  wait: true,
  blocking: true,
  spawn: true,
  nested: true,
  children: true,
  subagents: true,
  resume: true,
  detach: true,
  toolset: true,
  tools: true,
};
const RESEARCH_TOOLS: Record<string, true> = {
  ...FILE_TOOLS,
  task: true,
  todo: true,
  yield: true,
  broker_finalize: true,
};

const MAX_OUTPUT_BYTES = 1_000_000;
const MAX_BASH_SECONDS = 3_600;
const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
const SELECTOR = /^(.*):(?:(?:raw:)?(?:\d+(?:-\d+|\+\d+)?(?:,\d+(?:-\d+|\+\d+)?)*)|conflicts|raw)$/;
const GLOB_META = /[*?{[]/;
const AMBIGUOUS_PATH = /[\0\\\u00A0\u2000-\u200A\u202F\u205F\u3000]/;

type Context = { cwd: string; model?: { provider?: string; id?: string } };
type ToolEvent = { toolName?: unknown; input?: unknown };
type ToolCallDecision = { block: true; reason: string } | undefined;
type SessionStopDecision = { continue: true; additionalContext: string } | undefined;
type SchemaLike = {
  optional(): SchemaLike;
  describe(text: string): SchemaLike;
};
type ZodLike = {
  string(): SchemaLike;
  number(): SchemaLike;
  array(value: SchemaLike): SchemaLike;
  enum(values: string[]): SchemaLike;
  object(value: Record<string, SchemaLike>): SchemaLike;
};
type PiApi = {
  zod: ZodLike;
  on(name: "tool_call", handler: (event: ToolEvent, context: Context) => ToolCallDecision): void;
  on(name: "session_stop", handler: () => SessionStopDecision): void;
  registerTool(tool: Record<string, unknown>): void;
};

function blocked(reason: string): ToolCallDecision {
  return { block: true, reason };
}

function isResearchCaller(): boolean {
  return (process.env.OMP_DELEGATE_CALLER ?? "") === RESEARCH_CALLER;
}
function isReviewCaller(): boolean {
  return (process.env.OMP_DELEGATE_CALLER ?? "") === REVIEW_CALLER;
}
function usesStructuredResult(): boolean {
  return process.env.OMP_DELEGATE_STRUCTURED_RESULT === "1";
}



function researchTaskAllowed(input: unknown): string | undefined {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    return "task input must be an object";
  }
  const batch = input as Record<string, unknown>;
  for (const key of Object.keys(batch)) {
    if (Object.hasOwn(RESEARCH_SPAWN_CONTROLS, key)) {
      return `task must not set ${key}`;
    }
  }
  const tasks = batch.tasks;
  if (!Array.isArray(tasks)) {
    return "task batch must include a tasks array";
  }
  if (tasks.length > RESEARCH_MAX_TASKS) {
    return "task batch exceeds five children";
  }
  let sonnet = 0;
  let fable = 0;
  for (const item of tasks) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      return "task item must be an object";
    }
    const row = item as Record<string, unknown>;
    for (const key of Object.keys(row)) {
      if (Object.hasOwn(RESEARCH_SPAWN_CONTROLS, key)) {
        return `task item must not set ${key}`;
      }
    }
    const agent = row.agent;
    if (typeof agent !== "string" || !Object.hasOwn(RESEARCH_AGENTS, agent)) {
      return "task agent is not an admitted research agent";
    }
    if (RESEARCH_AGENTS[agent] === "fable") fable += 1;
    else sonnet += 1;
  }
  if (sonnet > RESEARCH_MAX_SONNET) return "task batch exceeds four Sonnet-class children";
  if (fable > RESEARCH_MAX_FABLE) return "task batch exceeds one Fable child";
  return undefined;
}



function existingAncestor(path: string): string | null {
  let cursor = path;
  while (!existsSync(cursor)) {
    try {
      if (lstatSync(cursor).isSymbolicLink()) return null;
    } catch {}
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return realpathSync(cursor);
}

function withinWorkspace(candidate: string, workspace: string): boolean {
  const rel = relative(workspace, candidate);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

function plainPath(raw: string): string | null {
  if (raw === "/") return ".";
  if (raw !== raw.trim() || URI_SCHEME.test(raw)) return null;
  const selector = raw.match(SELECTOR);
  const path = selector ? selector[1] : raw;
  if (
    path.includes(":")
    || AMBIGUOUS_PATH.test(path)
    || ["~", "@", ":", "[", "'", "\""].some((prefix) => path.startsWith(prefix))
  ) return null;
  return path;
}

function globBase(path: string): string {
  const match = GLOB_META.exec(path);
  if (!match) return path;
  const prefix = path.slice(0, match.index);
  return prefix.endsWith("/") ? prefix : dirname(prefix || ".");
}

function pathAllowed(
  raw: unknown,
  workspace: string,
  glob = false,
  roots: string[] = [workspace],
): boolean {
  if (typeof raw !== "string") return false;
  const plain = plainPath(raw);
  if (plain === null) return false;
  const candidate = resolve(workspace, glob ? globBase(plain) : plain);
  const canonical = existsSync(candidate) ? realpathSync(candidate) : existingAncestor(candidate);
  return canonical !== null && roots.some((root) => {
    try {
      return withinWorkspace(canonical, realpathSync(root));
    } catch {
      return false;
    }
  });
}

function pathsAllowed(
  raw: unknown,
  workspace: string,
  glob = false,
  roots: string[] = [workspace],
): boolean {
  if (raw === undefined || raw === null || raw === "") return true;
  if (typeof raw !== "string" || /[,\s]/.test(raw)) return false;
  return raw.split(";").every((item) => pathAllowed(item.trim(), workspace, glob, roots));
}

function editPaths(input: unknown): string[] | null {
  if (!input || typeof input !== "object" || !("input" in input)) return null;
  const patch = input.input;
  if (typeof patch !== "string") return null;
  const paths = [...patch.matchAll(/^\[([^#\n]+)#[0-9A-F]{4}\]$/gm)].map((match) => match[1]);
  if (paths.length === 0) return null;
  for (const match of patch.matchAll(/^MV (.+)$/gm)) {
    const value = match[1].trim();
    paths.push(value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value);
  }
  return paths;
}

function configuredReadRoots(workspace: string): string[] {
  let values: unknown;
  try {
    values = JSON.parse(process.env.OMP_DELEGATE_READ_PATHS ?? "[]");
  } catch {
    return [workspace];
  }
  if (!Array.isArray(values) || !values.every((value) => typeof value === "string" && isAbsolute(value))) {
    return [workspace];
  }
  const roots = [workspace];
  for (const value of values) {
    const resolved = resolve(value);
    try {
      const metadata = lstatSync(resolved);
      if (
        value !== resolved
        || metadata.isSymbolicLink()
        || (!metadata.isFile() && !metadata.isDirectory())
        || realpathSync(resolved) !== resolved
      ) {
        continue;
      }
      roots.push(resolved);
    } catch {
      continue;
    }
  }
  return roots;
}

function configuredWritePatterns(): RegExp[] {
  let values: unknown;
  try {
    values = JSON.parse(process.env.OMP_DELEGATE_WRITE_PATTERNS ?? "[]");
  } catch {
    return [];
  }
  if (!Array.isArray(values) || !values.every((value) => typeof value === "string")) return [];
  return values.map((value) => {
    // `**` crosses path separators; a single `*` never does. `**` is swapped
    // through a placeholder so the single-star pass cannot see its halves.
    const escaped = value.replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replaceAll("**", "\u0000")
      .replaceAll("*", "[^/]*")
      .replaceAll("\u0000", ".*");
    return new RegExp(`^${escaped}$`);
  });
}

function restrictedWriteAllowed(raw: unknown, workspace: string): boolean {
  if (typeof raw !== "string" || URI_SCHEME.test(raw) || !pathAllowed(raw, workspace)) return false;
  const candidate = resolve(workspace, raw);
  if (process.env.OMP_DELEGATE_CREATE_ONLY === "1" && existsSync(candidate)) return false;
  const rel = relative(workspace, candidate);
  return configuredWritePatterns().some((pattern) => pattern.test(rel));
}

function tokenizeGitCommand(command: string): string[] | null {
  // Wiki filenames carry spaces, so scoped git must honour shell quoting.
  // Single and double quotes group; no escape processing (the metacharacter
  // gate above already rejected `$` and backslashes stay literal, which git
  // treats as path bytes). Unbalanced quotes reject the whole command.
  const tokens: string[] = [];
  let current = "";
  let quote: string | null = null;
  let started = false;
  for (const ch of command) {
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
    } else if (/\s/.test(ch)) {
      if (started) {
        tokens.push(current);
        current = "";
        started = false;
      }
    } else {
      current += ch;
      started = true;
    }
  }
  if (quote) return null;
  if (started) tokens.push(current);
  return tokens;
}

function isReadableRef(arg: string): boolean {
  // A ref-shaped token for the read verbs (diff/log): branch names, tags,
  // remote refs like origin/master, commit SHAs, and HEAD~1-style suffixes.
  // No leading dot or slash and no traversal component — pathspec-looking
  // arguments fall through to the write-pattern check instead.
  return /^[A-Za-z0-9_][A-Za-z0-9_./~-]*$/.test(arg) && !arg.includes("/../");
}

function scopedGitCommandAllowed(input: unknown, workspace: string): boolean {
  if (process.env.OMP_DELEGATE_GIT_MODE !== "scoped"
    || !input || typeof input !== "object" || !("command" in input)
    || typeof input.command !== "string") return false;
  const command = input.command.trim();
  if (/[;&|`$<>\n\r]/.test(command)) return false;
  const tokens = tokenizeGitCommand(command);
  if (tokens === null) return false;
  if (tokens[0] !== "git") return false;
  const subcommand = tokens[1];
  const args = tokens.slice(2);
  if (subcommand === "status") {
    const allowed: Record<string, true> = {
      "--short": true,
      "--branch": true,
      "--porcelain": true,
      "--porcelain=v1": true,
      "--porcelain=v2": true,
      "-s": true,
      "-b": true,
      "-sb": true,
    };
    return args.every((arg) => Object.hasOwn(allowed, arg));
  }
  if (subcommand === "log") {
    return args.every((arg, index) =>
      ["--oneline", "--decorate", "--no-decorate"].includes(arg)
      || /^-n\d+$/.test(arg)
      || (arg === "-n" && /^\d+$/.test(args[index + 1] ?? ""))
      || (index > 0 && args[index - 1] === "-n" && /^\d+$/.test(arg))
      || isReadableRef(arg)
    );
  }
  if (subcommand === "diff") {
    const allowed: Record<string, true> = {
      "--check": true,
      "--stat": true,
      "--name-only": true,
      "--name-status": true,
      "--cached": true,
      "--staged": true,
      "--exit-code": true,
      "--quiet": true,
      "--no-ext-diff": true,
      "--relative": true,
      "--": true,
    };
    return args.every((arg) => Object.hasOwn(allowed, arg)
      || isReadableRef(arg)
      || restrictedWriteAllowed(arg, workspace));
  }
  if (subcommand === "add") {
    const paths = args.filter((arg) => arg !== "--");
    return paths.length > 0 && paths.every((path) => restrictedWriteAllowed(path, workspace));
  }
  if (subcommand === "mv") {
    // Stage promotion and archiving move a note between admitted folders.
    // Both ends must satisfy the write patterns; nothing leaves the boundary.
    const paths = args.filter((arg) => arg !== "--");
    return paths.length === 2 && paths.every((path) => restrictedWriteAllowed(path, workspace));
  }
  // The maturation writer must land exact Backlog-Run/Backlog-Request
  // trailer lines, but the one-command grammar cannot carry a newline and
  // three -m args stay denied; --trailer emits canonical trailer lines from
  // single-line "Key: value" arguments (g7, 2026-08-26).
  //
  // Some admitted callers commit in repositories whose git hooks cannot
  // execute inside the delegated bash sandbox: bwrap mounts only the
  // workspace plus system roots, so hook runtimes that resolve through the
  // user's home (venv interpreters symlinked to managed toolchains, hook
  // environment caches) dangle. Policy marks such callers hookless and the
  // broker passes OMP_DELEGATE_HOOKLESS_COMMIT=1; those callers alone may
  // append ONE trailing --no-verify to the exact contract form. Their
  // writes stay confined by write-patterns and reviewed after the run;
  // every other caller keeps the hook-bound form.
  if (subcommand === "commit") {
    const hooklessCommit = process.env.OMP_DELEGATE_HOOKLESS_COMMIT === "1";
    const subject = "(?: -m (?:'[^']+'|\"[^\"]+\")){1,2}";
    const trailers =
      "(?: --trailer (?:'[^'\\n]+: [^'\\n]+'|\"[^\"\\n]+: [^\"\\n]+\")){0,2}";
    const grammar = new RegExp(
      `^git commit${subject}${trailers}${hooklessCommit ? "(?: --no-verify)?" : ""}$`,
    );
    return grammar.test(command);
  }
  return false;
}


function fileToolAllowed(
  name: string,
  input: unknown,
  workspace: string,
  sandbox: string,
): boolean {
  const readRoots = configuredReadRoots(workspace);
  if (!input || typeof input !== "object") return false;
  if (name === "read" && "path" in input) {
    return pathAllowed(input.path, workspace, false, readRoots);
  }
  if (name === "write" && "path" in input) {
    if (sandbox === "restricted-write") {
      return restrictedWriteAllowed(input.path, workspace);
    }
    return sandbox === "workspace-write" && pathAllowed(input.path, workspace);
  }
  if (name === "grep" && "path" in input) {
    return pathsAllowed(input.path, workspace, false, readRoots);
  }
  if (name === "glob" && "path" in input) {
    return pathsAllowed(input.path, workspace, true, readRoots);
  }
  if (name === "edit") {
    const paths = editPaths(input);
    if (paths === null) return false;
    if (sandbox === "restricted-write") {
      return paths.every((path) => restrictedWriteAllowed(path, workspace));
    }
    return sandbox === "workspace-write"
      && paths.every((path) => pathAllowed(path, workspace));
  }
  return false;
}

function sandboxDirectories(workspace: string): string[] {
  const directories: string[] = [];
  let cursor = dirname(workspace);
  while (cursor !== "/" && cursor !== ".") {
    directories.unshift(cursor);
    cursor = dirname(cursor);
  }
  return directories;
}

function gitCommonDirectory(workspace: string): string {
  const result = spawnSync(
    "git",
    [
      "-c", `safe.directory=${workspace}`,
      "-C", workspace,
      "rev-parse", "--path-format=absolute", "--git-common-dir",
    ],
    {
      encoding: "utf8",
      env: { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" },
    },
  );
  if (result.status !== 0 || !result.stdout.trim()) {
    throw new Error("Scoped Git metadata could not be resolved for the admitted workspace");
  }
  return realpathSync(result.stdout.trim());
}

export function buildSandboxArgv(command: string, workspaceValue: string): string[] {
  const workspace = realpathSync(workspaceValue);
  const writable = ["workspace-write", "restricted-write"].includes(
    process.env.OMP_DELEGATE_SANDBOX ?? "",
  );
  const scopedGit = process.env.OMP_DELEGATE_GIT_MODE === "scoped";
  const commonDirectory = scopedGit ? gitCommonDirectory(workspace) : null;
  const argv = [
    "/usr/bin/bwrap",
    "--die-with-parent",
    "--new-session",
    "--unshare-all",
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--ro-bind", "/etc", "/etc",
    "--dev", "/dev",
    "--proc", "/proc",
    "--tmpfs", "/tmp",
    "--dir", "/tmp/home",
  ];
  const directories = new Set(sandboxDirectories(workspace));
  if (commonDirectory && !withinWorkspace(commonDirectory, workspace)) {
    for (const directory of sandboxDirectories(commonDirectory)) directories.add(directory);
  }
  for (const directory of directories) {
    if (!["/usr", "/etc", "/tmp"].includes(directory)) argv.push("--dir", directory);
  }
  if (commonDirectory && !withinWorkspace(commonDirectory, workspace)) {
    argv.push("--bind", commonDirectory, commonDirectory);
  }
  argv.push(
    writable ? "--bind" : "--ro-bind", workspace, workspace,
    "--chdir", workspace,
    "--setenv", "HOME", "/tmp/home",
    "--setenv", "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  );
  if (scopedGit) {
    argv.push(
      "--setenv", "GIT_CONFIG_COUNT", "1",
      "--setenv", "GIT_CONFIG_KEY_0", "safe.directory",
      "--setenv", "GIT_CONFIG_VALUE_0", workspace,
    );
  }
  argv.push("/bin/bash", "-c", command);
  return argv;
}

function killGroup(pid: number | undefined): void {
  if (pid === undefined) return;
  try {
    process.kill(-pid, "SIGTERM");
  } catch {}
  const timer = setTimeout(() => {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {}
  }, 2_000);
  timer.unref();
}

async function runSandboxedBash(
  command: string,
  timeoutValue: unknown,
  context: Context,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  const timeoutSeconds = typeof timeoutValue === "number" && Number.isFinite(timeoutValue)
    ? Math.max(1, Math.min(Math.floor(timeoutValue), MAX_BASH_SECONDS))
    : 120;
  const sandboxArgv = buildSandboxArgv(command, context.cwd);
  const child = spawn(sandboxArgv[0], sandboxArgv.slice(1), {
    cwd: context.cwd,
    detached: true,
    env: {
      PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  let bytes = 0;
  let outputExceeded = false;
  const collect = (target: Buffer[]) => (chunk: Buffer) => {
    bytes += chunk.length;
    if (bytes > MAX_OUTPUT_BYTES) {
      outputExceeded = true;
      killGroup(child.pid);
      return;
    }
    target.push(chunk);
  };
  child.stdout.on("data", collect(stdout));
  child.stderr.on("data", collect(stderr));
  const onAbort = () => killGroup(child.pid);
  signal?.addEventListener("abort", onAbort, { once: true });
  const timer = setTimeout(() => killGroup(child.pid), timeoutSeconds * 1_000);
  const { promise, resolve: resolveExit } = Promise.withResolvers<number | null>();
  child.once("error", () => resolveExit(127));
  child.once("exit", (code) => resolveExit(code));
  const exitCode = await promise;
  clearTimeout(timer);
  signal?.removeEventListener("abort", onAbort);
  const text = Buffer.concat([
    ...stdout,
    ...(stderr.length ? [Buffer.from("\n[stderr]\n"), ...stderr] : []),
  ]).toString("utf8");
  const failed = exitCode !== 0 || outputExceeded || signal?.aborted === true;
  return {
    content: [{
      type: "text",
      text: outputExceeded ? "Command output exceeded the 1,000,000-byte bound" : text || `(exit ${exitCode})`,
    }],
    details: { exitCode, outputExceeded },
    isError: failed,
  };
}

type Finding = {
  file: string;
  lines: number[];
  severity: "low" | "medium" | "high" | "critical";
  issue: string;
  fix: string;
};
type FinalResult = {
  summary: string;
  verification: string[];
  gaps: string[];
  verdict: "MET" | "PARTIALLY MET" | "NOT MET";
  served_model?: string;
  findings?: Finding[];
  structured_result?: string;
};

function meaningfulLines(value: string): string[] | null {
  const lines = value.split("\n").map((line) => line.trim()).filter(Boolean);
  if (lines.length > 50 || lines.some((line) => line.length < 4 || line.length > 1_000)) return null;
  return lines;
}

function normalizeFinding(value: unknown): Finding | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const finding = value as Record<string, unknown>;
  const keys = Object.keys(finding);
  const expected = ["file", "fix", "issue", "lines", "severity"];
  if (keys.length !== expected.length || keys.some((key) => !expected.includes(key))) return null;
  const file = finding.file;
  const lines = finding.lines;
  const severity = finding.severity;
  const issue = finding.issue;
  const fix = finding.fix;
  if (typeof file !== "string" || file.length < 1 || file.length > 1_000
    || isAbsolute(file) || AMBIGUOUS_PATH.test(file) || file.includes("\n")
    || file.split("/").some((part) => !part || part === "." || part === "..")) return null;
  if (!Array.isArray(lines) || lines.length < 1 || lines.length > 20
    || lines.some((line) => !Number.isInteger(line) || line < 1 || line > 10_000_000)
    || new Set(lines).size !== lines.length
    || lines.some((line, index) => index > 0 && Number(lines[index - 1]) >= Number(line))) return null;
  if (!["low", "medium", "high", "critical"].includes(String(severity))) return null;
  if (typeof issue !== "string" || issue.trim().length < 4 || issue.length > 2_000
    || typeof fix !== "string" || fix.trim().length < 4 || fix.length > 2_000) return null;
  return {
    file,
    lines: lines as number[],
    severity: severity as Finding["severity"],
    issue: issue.trim(),
    fix: fix.trim(),
  };
}

function normalizeFinal(value: unknown): FinalResult | null {
  if (!value || typeof value !== "object"
    || !("summary" in value) || !("verification" in value)
    || !("gaps" in value) || !("verdict" in value)
    || typeof value.summary !== "string"
    || typeof value.verification !== "string"
    || typeof value.gaps !== "string"
    || !["MET", "PARTIALLY MET", "NOT MET"].includes(String(value.verdict))) return null;
  const summary = value.summary.trim();
  const verification = meaningfulLines(value.verification);
  const gaps = meaningfulLines(value.gaps);
  if (summary.length < 20 || summary.length > 4_000 || verification === null || gaps === null) return null;
  const verdict = value.verdict as FinalResult["verdict"];
  if (verdict === "MET" && (verification.length === 0 || gaps.length !== 0)) return null;
  if (verdict === "PARTIALLY MET" && (verification.length === 0 || gaps.length === 0)) return null;
  if (verdict === "NOT MET" && gaps.length === 0) return null;
  if (isReviewCaller()) {
    if (!("findings" in value) || !Array.isArray(value.findings)
      || value.findings.length > 32) return null;
    const findings = value.findings.map(normalizeFinding);
    if (findings.some((finding) => finding === null)) return null;
    return { summary, verification, gaps, verdict, findings: findings as Finding[] };
  }
  if (usesStructuredResult()) {
    if (!("structured_result" in value)
      || typeof value.structured_result !== "string"
      || Buffer.byteLength(value.structured_result, "utf8") > 500_000) return null;
    try {
      const parsed = JSON.parse(value.structured_result);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    } catch {
      return null;
    }
    return { summary, verification, gaps, verdict, structured_result: value.structured_result };
  }
  if ("findings" in value || "structured_result" in value) return null;
  return { summary, verification, gaps, verdict };
}

function servedModel(context: Context | undefined): string | undefined {
  const model = context?.model;
  if (!model) return undefined;
  const provider = typeof model.provider === "string" ? model.provider : "";
  const id = typeof model.id === "string" ? model.id : "";
  if (!provider || !id) return undefined;
  return `${provider}/${id}`;
}

export default function ompDelegateExtension(pi: PiApi): void {
  let finalized = false;
  let corrections = 0;
  // A run that ends without broker_finalize leaves no typed result at all.
  // Spend exactly one continuation, with the session context still intact, on
  // asking for it; a second unfinalized stop settles and fails as before.
  pi.on("session_stop", () => {
    if (finalized || corrections > 0) return undefined;
    corrections += 1;
    return {
      continue: true,
      additionalContext: isReviewCaller()
        ? "This review run cannot end: broker_finalize was never called, so the caller receives no result. Call broker_finalize exactly once, now, with the typed result of the review already completed: a summary of at least 20 characters, newline-separated verification statements, newline-separated gaps, a verdict of MET, PARTIALLY MET, or NOT MET, and structured findings using file, lines, severity, issue, and fix. Report the review as it actually stands; do not start new work and do not call any other tool."
        : usesStructuredResult()
          ? "This structured-result run cannot end: broker_finalize was never called. Call broker_finalize exactly once with summary, newline-separated verification and gaps, the honest verdict, and structured_result containing the exact project-required JSON object. Do not start new work or call another tool."
          : "This run cannot end: broker_finalize was never called, so the caller receives no result. Call broker_finalize exactly once, now, with the typed result of the work already done: a summary of at least 20 characters, newline-separated verification statements, newline-separated gaps, and a verdict of MET, PARTIALLY MET, or NOT MET. Report the work as it actually stands; do not start new work and do not call any other tool.",
    };
  });
  pi.on("tool_call", (event, context) => {
    const name = typeof event.toolName === "string" ? event.toolName : "";
    const research = isResearchCaller();
    if (finalized) return blocked("The final result is already recorded; no later tool calls are allowed");
    if (!Object.hasOwn(research ? RESEARCH_TOOLS : ALLOWED_TOOLS, name)) {
      return blocked("Tool is outside the OMP delegation workspace policy");
    }
    if (research && name === "task") {
      const reason = researchTaskAllowed(event.input);
      return reason ? blocked(reason) : undefined;
    }
    const workspace = realpathSync(context.cwd);
    const configuredSandbox = process.env.OMP_DELEGATE_SANDBOX ?? "";
    const sandbox = research ? "restricted-write" : configuredSandbox;
    if (name === "bash" && sandbox !== "workspace-write") {
      return sandbox === "restricted-write" && scopedGitCommandAllowed(event.input, workspace)
        ? undefined
        : blocked("Command is outside the admitted OMP delegation policy");
    }
    if (!Object.hasOwn(FILE_TOOLS, name)) return undefined;
    return fileToolAllowed(name, event.input, workspace, sandbox)
      ? undefined
      : blocked("Path is outside the admitted OMP delegation workspace");
  });

  const z = pi.zod;
  if (!isResearchCaller()) {
    const scopedGitOnly = process.env.OMP_DELEGATE_SANDBOX === "restricted-write"
      && process.env.OMP_DELEGATE_GIT_MODE === "scoped";
    const hooklessCommit = process.env.OMP_DELEGATE_HOOKLESS_COMMIT === "1";
    const bashTool = {
      name: "bash",
      label: scopedGitOnly ? "Scoped Git" : "Sandboxed Bash",
      description: scopedGitOnly
        ? `Run one allowlisted Git command in the admitted workspace. Allowed forms: git status, git log, git diff, git add with admitted paths, git mv between admitted paths, and git commit -m '<subject>' with up to two --trailer 'Key: value' flags for attribution trailers${hooklessCommit ? ", plus one trailing --no-verify (git hooks cannot execute in this sandbox — commit with it rather than leaving the work staged)" : ""}. General shell commands are denied.`
        : "Run one command inside a networkless bubblewrap sandbox limited to the admitted workspace.",
      parameters: z.object({
        command: z.string().describe(scopedGitOnly ? "One exact allowlisted Git command" : "Command to run"),
        timeout: z.number().optional().describe("Timeout in seconds"),
      }),
      approval: "exec",
      hidden: false,
      defaultInactive: false,
      loadMode: "essential",
      deferrable: false,
      buildSandboxArgv,
      async execute(_id: string, params: { command: string; timeout?: number }, signal: AbortSignal | undefined, _update: unknown, context: Context) {
        return runSandboxedBash(params.command, params.timeout, context, signal);
      },
    };
    pi.registerTool(bashTool);
  }
  const commonFinalizeParameters: Record<string, SchemaLike> = {
    summary: z.string().describe("Meaningful outcome summary, at least 20 characters"),
    verification: z.string().describe("Newline-separated verification statements; required for MET and PARTIALLY MET"),
    gaps: z.string().describe("Newline-separated gaps; required for PARTIALLY MET and NOT MET; empty for MET"),
    verdict: z.enum(["MET", "PARTIALLY MET", "NOT MET"]),
  };
  const findingParameters = z.object({
    file: z.string().describe("Repository-relative path"),
    lines: z.array(z.number()).describe("Sorted positive source lines"),
    severity: z.enum(["low", "medium", "high", "critical"]),
    issue: z.string().describe("Actionable defect"),
    fix: z.string().describe("Bounded correction"),
  });
  const finalizeParameters = z.object(isReviewCaller()
    ? {
      ...commonFinalizeParameters,
      findings: z.array(findingParameters).describe("Typed review findings; empty only when the review found no actionable defects"),
    }
    : usesStructuredResult()
      ? {
        ...commonFinalizeParameters,
        structured_result: z.string().describe("Exact project-required JSON object encoded as a string"),
      }
      : commonFinalizeParameters);



  pi.registerTool({
    name: "broker_finalize",
    label: "Finalize broker result",
    description: isReviewCaller()
      ? "Record the broker's required typed review outcome. Call exactly once. Findings are structured objects; verification and gaps are newline-separated text."
      : usesStructuredResult()
        ? "Record the project-owned structured outcome exactly once. structured_result is the exact task-required JSON object encoded as a JSON string."
        : "Record the broker's required typed outcome. Call exactly once, after all edits and verification. Verification and gaps are newline-separated text, not arrays.",
    parameters: finalizeParameters,
    approval: "write",
    hidden: false,
    defaultInactive: false,
    loadMode: "essential",
    deferrable: false,
    async execute(_id: string, params: unknown, _signal?: AbortSignal, _update?: unknown, context?: Context) {
      if (finalized) {
        return { content: [{ type: "text", text: "Final result was already recorded" }], isError: true };
      }
      const finalPath = process.env.OMP_DELEGATE_FINAL_PATH;
      const final = normalizeFinal(params);
      if (!finalPath || final === null) {
        return { content: [{ type: "text", text: "Final result rejected: use a meaningful summary; newline-separated verification/gaps; MET requires verification and no gaps; PARTIALLY MET requires both; NOT MET requires gaps" }], isError: true };
      }
      const served = servedModel(context);
      const recorded = served === undefined ? final : { ...final, served_model: served };
      const temporary = `${finalPath}.tmp-${process.pid}`;
      writeFileSync(temporary, `${JSON.stringify(recorded)}\n`, { mode: 0o600, flag: "wx" });
      renameSync(temporary, finalPath);
      chmodSync(finalPath, 0o600);
      finalized = true;
      return { content: [{ type: "text", text: "Final result recorded; end the turn now" }], details: {} };
    },
  });
}
