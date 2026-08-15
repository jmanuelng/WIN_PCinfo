import { spawn, spawnSync } from "node:child_process";

export const READY_LABEL = "ready-for-agent";
export const BASE_REF = "origin/main";
export const MAX_ALLOWED_ITERATIONS = 10;
export const DEFAULT_MAX_PARALLEL_ISSUES = 2;
export const MAX_ALLOWED_PARALLEL_ISSUES = 2;
export const AGENT_PHASE_IDLE_TIMEOUT_SECONDS = 2 * 60 * 60;

export interface GitHubActor {
  readonly login: string;
}

export interface GitHubLabel {
  readonly name: string;
}

export interface RelationshipConnection {
  readonly nodes?: readonly unknown[];
  readonly totalCount?: number;
}

export interface SubIssuesSummary {
  readonly completed: number;
  readonly percentCompleted?: number;
  readonly total: number;
}

export interface GitHubIssue {
  readonly number: number;
  readonly title: string;
  readonly state: string;
  readonly url?: string;
  readonly labels?: readonly GitHubLabel[];
  readonly assignees?: readonly GitHubActor[];
  readonly blockedBy?: RelationshipConnection | readonly unknown[] | null;
  readonly subIssuesSummary?: SubIssuesSummary | null;
}

export interface StatusCheck {
  readonly __typename?: string;
  readonly name?: string;
  readonly context?: string;
  readonly workflowName?: string;
  readonly status?: string;
  readonly conclusion?: string | null;
  readonly state?: string;
}

export interface CheckSummary {
  readonly failed: readonly string[];
  readonly pending: readonly string[];
  readonly passed: readonly string[];
}

export function buildImplementationPhaseOptions<TAgent>(
  agent: TAgent,
  issueNumber: number,
  issueTitle: string,
) {
  return {
    name: `issue-${issueNumber}-implementer`,
    maxIterations: 1,
    idleTimeoutSeconds: AGENT_PHASE_IDLE_TIMEOUT_SECONDS,
    agent,
    promptFile: "./.sandcastle/implement-prompt.md",
    promptArgs: {
      ISSUE_NUMBER: issueNumber,
      ISSUE_TITLE: issueTitle,
    },
  } as const;
}

export function buildReviewPhaseOptions<TAgent>(
  agent: TAgent,
  issueNumber: number,
  branch: string,
) {
  return {
    name: `issue-${issueNumber}-reviewer`,
    maxIterations: 1,
    idleTimeoutSeconds: AGENT_PHASE_IDLE_TIMEOUT_SECONDS,
    agent,
    promptFile: "./.sandcastle/review-prompt.md",
    promptArgs: {
      ISSUE_NUMBER: issueNumber,
      BRANCH: branch,
      BASE_BRANCH: BASE_REF,
    },
  } as const;
}

export class SerializedExecutionStoppedError extends Error {
  constructor(cause: unknown) {
    super("Serialized execution stopped before this operation could begin.", {
      cause,
    });
    this.name = "SerializedExecutionStoppedError";
  }
}

export function createSerializedExecutor() {
  let tail = Promise.resolve();
  let stopped = false;
  let stopCause: unknown;

  function stop(cause: unknown): void {
    if (!stopped) {
      stopped = true;
      stopCause = cause;
    }
  }

  function execute<T>(operation: () => Promise<T>): Promise<T> {
    const current = tail.then(async () => {
      if (stopped) {
        throw new SerializedExecutionStoppedError(stopCause);
      }
      try {
        return await operation();
      } catch (error) {
        stop(error);
        throw error;
      }
    });
    tail = current.then(
      () => undefined,
      () => undefined,
    );
    return current;
  }

  return { execute, stop } as const;
}

export function buildIntegrationPhaseOptions<TAgent>(
  agent: TAgent,
  issueNumber: number,
  branch: string,
) {
  return {
    name: `issue-${issueNumber}-integrator`,
    maxIterations: 1,
    idleTimeoutSeconds: AGENT_PHASE_IDLE_TIMEOUT_SECONDS,
    agent,
    promptFile: "./.sandcastle/integration-prompt.md",
    promptArgs: {
      ISSUE_NUMBER: issueNumber,
      BRANCH: branch,
      BASE_BRANCH: BASE_REF,
    },
  } as const;
}

export interface RunOptions {
  readonly cwd?: string;
  readonly stream?: boolean;
  readonly allowFailure?: boolean;
  readonly timeoutMs?: number;
}

export interface CommandResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number;
}

function commandInvocation(command: string, args: readonly string[]) {
  if (process.platform === "win32" && command === "codex") {
    return {
      command: process.env.ComSpec || "cmd.exe",
      args: ["/d", "/s", "/c", "codex", ...args],
    };
  }

  return { command, args: [...args] };
}

export interface WorkflowCommandAdapter {
  readonly run: (
    command: string,
    args: readonly string[],
    options?: RunOptions,
  ) => CommandResult;
  readonly json: <T>(
    command: string,
    args: readonly string[],
    options?: RunOptions,
  ) => T;
}

function finalizeCommandResult(
  command: string,
  args: readonly string[],
  exitCode: number,
  stdout: string,
  stderr: string,
  allowFailure = false,
): CommandResult {
  const normalized = {
    stdout: stdout.trim(),
    stderr: stderr.trim(),
    exitCode,
  };
  if (exitCode !== 0 && !allowFailure) {
    const detail = [normalized.stdout, normalized.stderr]
      .filter(Boolean)
      .join("\n");
    throw new Error(
      `${command} ${args.join(" ")} exited with code ${exitCode}${detail ? `:\n${detail}` : ""}`,
    );
  }
  return normalized;
}

export function runCommand(
  command: string,
  args: readonly string[],
  options: RunOptions = {},
): CommandResult {
  const invocation = commandInvocation(command, args);
  const result = spawnSync(invocation.command, invocation.args, {
    cwd: options.cwd,
    encoding: "utf8",
    stdio: options.stream ? "inherit" : "pipe",
    timeout: options.timeoutMs,
    windowsHide: true,
  });

  if (result.error) {
    throw new Error(
      `Unable to run ${command}: ${result.error.message}`,
      { cause: result.error },
    );
  }

  const stdout = typeof result.stdout === "string" ? result.stdout.trim() : "";
  const stderr = typeof result.stderr === "string" ? result.stderr.trim() : "";
  return finalizeCommandResult(
    command,
    args,
    result.status ?? 1,
    stdout,
    stderr,
    options.allowFailure,
  );
}

export async function runCommandAsync(
  command: string,
  args: readonly string[],
  options: RunOptions = {},
): Promise<CommandResult> {
  const invocation = commandInvocation(command, args);
  return await new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(invocation.command, invocation.args, {
      cwd: options.cwd,
      windowsHide: true,
      stdio: options.stream ? "inherit" : ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout?.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr?.on("data", (chunk: Buffer) => stderr.push(chunk));

    let timedOut = false;
    const timeout = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          child.kill();
        }, options.timeoutMs)
      : undefined;

    child.once("error", (error) => {
      if (timeout) clearTimeout(timeout);
      reject(new Error(`Unable to run ${command}: ${error.message}`, { cause: error }));
    });
    child.once("close", (code) => {
      if (timeout) clearTimeout(timeout);
      const exitCode = code ?? 1;
      const stdoutText = Buffer.concat(stdout).toString("utf8").trim();
      const stderrText = Buffer.concat(stderr).toString("utf8").trim();
      if (timedOut) {
        reject(new Error(`${command} ${args.join(" ")} timed out.`));
        return;
      }
      try {
        resolve(
          finalizeCommandResult(
            command,
            args,
            exitCode,
            stdoutText,
            stderrText,
            options.allowFailure,
          ),
        );
      } catch (error) {
        reject(error);
      }
    });
  });
}

export function runJson<T>(
  command: string,
  args: readonly string[],
  options: RunOptions = {},
): T {
  const result = runCommand(command, args, options);
  try {
    return JSON.parse(result.stdout) as T;
  } catch (error) {
    throw new Error(
      `${command} returned malformed JSON: ${result.stdout || "<empty>"}`,
      { cause: error },
    );
  }
}

function activeOrUnknownRelationshipCount(
  relationship: RelationshipConnection | readonly unknown[] | null | undefined,
): number {
  const nodes = Array.isArray(relationship)
    ? relationship
    : relationship &&
        "nodes" in relationship &&
        Array.isArray(relationship.nodes)
      ? relationship.nodes
      : [];

  const incompleteRelationshipCount =
    !Array.isArray(relationship) &&
    relationship &&
    Number.isInteger(relationship.totalCount) &&
    (relationship.totalCount ?? 0) > nodes.length
      ? (relationship.totalCount ?? 0) - nodes.length
      : 0;

  return incompleteRelationshipCount + nodes.filter((node) => {
    if (!node || typeof node !== "object" || !("state" in node)) {
      return true;
    }

    const state = node.state;
    return typeof state !== "string" || state.toUpperCase() !== "CLOSED";
  }).length;
}

function hasReadyLabel(issue: GitHubIssue): boolean {
  return (issue.labels ?? []).some((label) => label.name === READY_LABEL);
}

const DEFAULT_WORKFLOW_COMMANDS: WorkflowCommandAdapter = {
  run: runCommand,
  json: runJson,
};

function hasNoOpenSubIssues(issue: GitHubIssue): boolean {
  const subIssues = issue.subIssuesSummary;
  return (
    subIssues !== null &&
    subIssues !== undefined &&
    Number.isInteger(subIssues.completed) &&
    Number.isInteger(subIssues.total) &&
    subIssues.total >= 0 &&
    subIssues.completed === subIssues.total
  );
}

export function isEligibleIssue(issue: GitHubIssue): boolean {
  return (
    issue.state.toUpperCase() === "OPEN" &&
    hasReadyLabel(issue) &&
    (issue.assignees ?? []).length === 0 &&
    activeOrUnknownRelationshipCount(issue.blockedBy) === 0 &&
    hasNoOpenSubIssues(issue)
  );
}

export function isSafelyClaimedIssue(
  issue: GitHubIssue,
  viewer: string,
): boolean {
  const assignees = issue.assignees ?? [];
  return (
    issue.state.toUpperCase() === "OPEN" &&
    hasReadyLabel(issue) &&
    activeOrUnknownRelationshipCount(issue.blockedBy) === 0 &&
    hasNoOpenSubIssues(issue) &&
    assignees.length === 1 &&
    assignees[0]?.login.toLowerCase() === viewer.toLowerCase()
  );
}

export function selectNextIssue(
  issues: readonly GitHubIssue[],
): GitHubIssue | undefined {
  return selectNextIssues(issues, 1)[0];
}

export function selectNextIssues(
  issues: readonly GitHubIssue[],
  limit: number,
): readonly GitHubIssue[] {
  if (!Number.isInteger(limit) || limit < 1) {
    throw new Error("Issue selection limit must be a positive integer.");
  }

  return [...issues]
    .filter(isEligibleIssue)
    .sort((left, right) => left.number - right.number)
    .slice(0, limit);
}

interface FrontierIssueNode {
  readonly number: number;
  readonly title: string;
  readonly state: string;
  readonly url: string;
  readonly labels: { readonly nodes: readonly GitHubLabel[] };
  readonly assignees: { readonly nodes: readonly GitHubActor[] };
  readonly blockedBy: RelationshipConnection;
  readonly subIssuesSummary: SubIssuesSummary | null;
}

interface FrontierPage {
  readonly data: {
    readonly repository: {
      readonly issues: {
        readonly nodes: readonly FrontierIssueNode[];
        readonly pageInfo: {
          readonly hasNextPage: boolean;
          readonly endCursor: string | null;
        };
      };
    };
  };
}

const FRONTIER_QUERY = `
  query($owner: String!, $name: String!, $cursor: String) {
    repository(owner: $owner, name: $name) {
      issues(
        first: 100
        after: $cursor
        states: OPEN
        labels: ["${READY_LABEL}"]
        orderBy: { field: CREATED_AT, direction: ASC }
      ) {
        nodes {
          number
          title
          state
          url
          labels(first: 100) { nodes { name } }
          assignees(first: 100) { nodes { login } }
          blockedBy(first: 100) { totalCount nodes { state } }
          subIssuesSummary { completed percentCompleted total }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
`;

export function listEligibleIssues(
  desiredCount = MAX_ALLOWED_PARALLEL_ISSUES,
  commands: WorkflowCommandAdapter = DEFAULT_WORKFLOW_COMMANDS,
): readonly GitHubIssue[] {
  if (!Number.isInteger(desiredCount) || desiredCount < 1) {
    throw new Error("Desired frontier count must be a positive integer.");
  }

  const repository = commands.run(
    "gh",
    ["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
  ).stdout;
  const [owner, name, ...unexpected] = repository.split("/");
  if (!owner || !name || unexpected.length > 0) {
    throw new Error(`GitHub CLI returned an invalid repository name: ${repository}`);
  }

  const issues: GitHubIssue[] = [];
  let cursor: string | null = null;
  while (true) {
    const args = [
      "api",
      "graphql",
      "-f",
      `query=${FRONTIER_QUERY}`,
      "-F",
      `owner=${owner}`,
      "-F",
      `name=${name}`,
    ];
    if (cursor) {
      args.push("-F", `cursor=${cursor}`);
    }
    const page = commands.json<FrontierPage>("gh", args);
    const connection = page.data.repository.issues;
    issues.push(
      ...connection.nodes.map((issue) => ({
        number: issue.number,
        title: issue.title,
        state: issue.state,
        url: issue.url,
        labels: issue.labels.nodes,
        assignees: issue.assignees.nodes,
        blockedBy: issue.blockedBy,
        subIssuesSummary: issue.subIssuesSummary,
      })),
    );

    if (selectNextIssues(issues, desiredCount).length >= desiredCount) {
      return issues;
    }
    if (!connection.pageInfo.hasNextPage) {
      return issues;
    }
    cursor = connection.pageInfo.endCursor;
    if (!cursor) {
      throw new Error("GitHub frontier pagination omitted its next cursor.");
    }
  }
}

export function claimIssue(issue: GitHubIssue): void {
  const viewer = runCommand("gh", ["api", "user", "--jq", ".login"]).stdout;
  if (!viewer) {
    throw new Error("GitHub CLI did not return the authenticated login.");
  }

  runCommand("gh", [
    "issue",
    "edit",
    String(issue.number),
    "--add-assignee",
    "@me",
  ]);

  const claimed = runJson<GitHubIssue>("gh", [
    "issue",
    "view",
    String(issue.number),
    "--json",
    "number,title,state,url,labels,assignees,blockedBy,subIssuesSummary",
  ]);
  if (!isSafelyClaimedIssue(claimed, viewer)) {
    runCommand(
      "gh",
      ["issue", "edit", String(issue.number), "--remove-assignee", "@me"],
      { allowFailure: true },
    );
    throw new Error(
      `Issue #${issue.number} changed while it was being claimed; the claim was released.`,
    );
  }
}

export function releaseIssueClaim(
  issueNumber: number,
  commands: WorkflowCommandAdapter = DEFAULT_WORKFLOW_COMMANDS,
): void {
  const viewer = commands.run(
    "gh",
    ["api", "user", "--jq", ".login"],
  ).stdout;
  if (!viewer) {
    throw new Error("GitHub CLI did not return the authenticated login.");
  }
  commands.run("gh", [
    "issue",
    "edit",
    String(issueNumber),
    "--remove-assignee",
    "@me",
  ]);
  const released = commands.json<GitHubIssue>("gh", [
    "issue",
    "view",
    String(issueNumber),
    "--json",
    "number,assignees",
  ]);
  if (
    (released.assignees ?? []).some(
      (assignee) => assignee.login.toLowerCase() === viewer.toLowerCase(),
    )
  ) {
    throw new Error(`Issue #${issueNumber} claim rollback could not be verified.`);
  }
}

export function refreshBase(): string {
  runCommand("git", ["fetch", "origin", "main"]);
  return runCommand("git", ["rev-parse", "--verify", BASE_REF]).stdout;
}

export function assertAuthentication(): void {
  runCommand("gh", ["auth", "status"]);
  runCommand("codex", ["login", "status"]);
}

export function assertHostReady(): void {
  const status = runCommand("git", ["status", "--porcelain"]).stdout;
  if (status) {
    throw new Error(
      `The host worktree must be clean before Sandcastle starts:\n${status}`,
    );
  }

  const branch = runCommand("git", ["branch", "--show-current"]).stdout;
  if (branch !== "main") {
    throw new Error(`Sandcastle must start from local main, not ${branch || "detached HEAD"}.`);
  }

  const remoteHead = refreshBase();
  const localHead = runCommand("git", ["rev-parse", "HEAD"]).stdout;
  if (localHead !== remoteHead) {
    throw new Error(
      `Local main must exactly match ${BASE_REF} before Sandcastle starts. Run git pull --ff-only origin main.`,
    );
  }
}

export function syncLocalMain(): string {
  const remoteHead = refreshBase();
  runCommand("git", ["merge", "--ff-only", BASE_REF]);
  const localHead = runCommand("git", ["rev-parse", "HEAD"]).stdout;
  if (localHead !== remoteHead) {
    throw new Error(`Local main did not fast-forward to ${BASE_REF}.`);
  }
  return localHead;
}

function checkName(check: StatusCheck): string {
  return check.name || check.context || check.workflowName || "unnamed check";
}

export function analyzeChecks(checks: readonly StatusCheck[]): CheckSummary {
  const failureStates = new Set([
    "ACTION_REQUIRED",
    "CANCELLED",
    "ERROR",
    "FAILURE",
    "SKIPPED",
    "STALE",
    "STARTUP_FAILURE",
    "TIMED_OUT",
  ]);
  const successStates = new Set(["SUCCESS", "NEUTRAL"]);
  const failed: string[] = [];
  const pending: string[] = [];
  const passed: string[] = [];

  for (const check of checks) {
    const outcome = (check.conclusion || check.state || "").toUpperCase();
    const status = (check.status || "").toUpperCase();
    const name = checkName(check);
    if (failureStates.has(outcome)) {
      failed.push(name);
    } else if (successStates.has(outcome)) {
      passed.push(name);
    } else if (status === "COMPLETED" && !outcome) {
      failed.push(`${name} (completed without a conclusion)`);
    } else {
      pending.push(name);
    }
  }

  return { failed, pending, passed };
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export async function waitForPullRequestChecks(
  pullRequestUrl: string,
  timeoutMs = 30 * 60 * 1000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    const pullRequest = runJson<{
      readonly state: string;
      readonly statusCheckRollup: readonly StatusCheck[];
    }>("gh", [
      "pr",
      "view",
      pullRequestUrl,
      "--json",
      "state,statusCheckRollup",
    ]);

    if (pullRequest.state.toUpperCase() !== "OPEN") {
      throw new Error(
        `Pull request left the OPEN state before merge: ${pullRequest.state}`,
      );
    }

    const summary = analyzeChecks(pullRequest.statusCheckRollup ?? []);
    if (summary.failed.length > 0) {
      throw new Error(`Pull request checks failed: ${summary.failed.join(", ")}`);
    }
    if (summary.pending.length === 0) {
      console.log(
        summary.passed.length > 0
          ? `Pull request checks passed: ${summary.passed.join(", ")}`
          : "No pull request checks are configured; local full-suite validation is authoritative.",
      );
      return;
    }
    if (Date.now() >= deadline) {
      throw new Error(
        `Timed out waiting for pull request checks: ${summary.pending.join(", ")}`,
      );
    }

    console.log(`Waiting for checks: ${summary.pending.join(", ")}`);
    await sleep(10_000);
  }
}

export function pushAndCreatePullRequest(
  issue: GitHubIssue,
  branch: string,
): { readonly url: string; readonly number: number } {
  runCommand("git", ["push", "--set-upstream", "origin", branch]);
  runCommand("gh", [
    "pr",
    "create",
    "--base",
    "main",
    "--head",
    branch,
    "--title",
    issue.title,
    "--body",
    `Closes #${issue.number}\n\nImplemented and independently reviewed by the repository Sandcastle workflow. The complete PowerShell test suite passed before delivery.`,
  ]);

  return runJson<{ readonly url: string; readonly number: number }>("gh", [
    "pr",
    "view",
    branch,
    "--json",
    "url,number",
  ]);
}

export function mergePullRequest(
  pullRequestUrl: string,
  headSha: string,
): void {
  runCommand("gh", [
    "pr",
    "merge",
    pullRequestUrl,
    "--squash",
    "--delete-branch",
    "--match-head-commit",
    headSha,
  ]);

  const merged = runJson<{
    readonly state: string;
    readonly mergedAt: string | null;
  }>("gh", [
    "pr",
    "view",
    pullRequestUrl,
    "--json",
    "state,mergedAt",
  ]);
  if (!merged.mergedAt || merged.state.toUpperCase() !== "MERGED") {
    throw new Error(`Pull request did not reach MERGED state: ${pullRequestUrl}`);
  }
}

export function ensureIssueClosed(
  issueNumber: number,
  pullRequestUrl: string,
): void {
  const issue = runJson<{ readonly state: string }>("gh", [
    "issue",
    "view",
    String(issueNumber),
    "--json",
    "state",
  ]);
  if (issue.state.toUpperCase() === "CLOSED") {
    return;
  }

  runCommand("gh", [
    "issue",
    "close",
    String(issueNumber),
    "--comment",
    `Completed and merged by Sandcastle in ${pullRequestUrl}.`,
  ]);
}

export function parseMaxIterations(args: readonly string[]): number {
  const flagIndex = args.indexOf("--max-iterations");
  if (flagIndex === -1) {
    return MAX_ALLOWED_ITERATIONS;
  }

  const value = Number.parseInt(args[flagIndex + 1] ?? "", 10);
  if (!Number.isInteger(value) || value < 1 || value > MAX_ALLOWED_ITERATIONS) {
    throw new Error(
      `--max-iterations must be an integer from 1 through ${MAX_ALLOWED_ITERATIONS}.`,
    );
  }
  return value;
}

export function parseMaxParallel(args: readonly string[]): number {
  const flagIndex = args.indexOf("--max-parallel");
  if (flagIndex === -1) {
    return DEFAULT_MAX_PARALLEL_ISSUES;
  }

  const value = Number.parseInt(args[flagIndex + 1] ?? "", 10);
  if (
    !Number.isInteger(value) ||
    value < 1 ||
    value > MAX_ALLOWED_PARALLEL_ISSUES
  ) {
    throw new Error(
      `--max-parallel must be an integer from 1 through ${MAX_ALLOWED_PARALLEL_ISSUES}.`,
    );
  }
  return value;
}
