import * as sandcastle from "@ai-hero/sandcastle";
import { noSandbox } from "@ai-hero/sandcastle/sandboxes/no-sandbox";
import {
  BASE_REF,
  assertAuthentication,
  assertHostReady,
  buildImplementationPhaseOptions,
  buildIntegrationPhaseOptions,
  buildReviewPhaseOptions,
  claimIssue,
  createSerializedExecutor,
  ensureIssueClosed,
  listEligibleIssues,
  mergePullRequest,
  parseMaxIterations,
  parseMaxParallel,
  pushAndCreatePullRequest,
  refreshBase,
  releaseIssueClaim,
  runCommand,
  runCommandAsync,
  selectNextIssues,
  syncLocalMain,
  waitForPullRequestChecks,
  type GitHubIssue,
} from "./workflow.mts";
import { createCodexAgent } from "./codex-agent.mts";

const cliArgs = process.argv.slice(2);
const maxIterations = parseMaxIterations(cliArgs);
const maxParallel = parseMaxParallel(cliArgs);
const agent = createCodexAgent();

async function closeSandbox(
  sandbox: Awaited<ReturnType<typeof sandcastle.createSandbox>>,
): Promise<void> {
  const closeResult = await sandbox.close();
  if (closeResult.preservedWorktreePath) {
    console.error(
      `Sandcastle preserved a dirty worktree at ${closeResult.preservedWorktreePath}`,
    );
  }
}

function assertCleanDeliverable(worktreePath: string, branch: string): void {
  const dirty = runCommand(
    "git",
    ["status", "--porcelain"],
    { cwd: worktreePath },
  ).stdout;
  if (dirty) {
    throw new Error(
      `Agent worktree is dirty after review and validation:\n${dirty}`,
    );
  }

  const ahead = Number.parseInt(
    runCommand(
      "git",
      ["rev-list", "--count", `${BASE_REF}..HEAD`],
      { cwd: worktreePath },
    ).stdout,
    10,
  );
  if (!Number.isInteger(ahead) || ahead < 1) {
    throw new Error(`Branch ${branch} contains no deliverable commits.`);
  }
}

async function prepareIssue(issue: GitHubIssue) {
  const branch = `sandcastle/issue-${issue.number}-${Date.now()}`;
  const sandbox = await sandcastle.createSandbox({
    branch,
    baseBranch: BASE_REF,
    sandbox: noSandbox(),
  });

  try {
    const implementation = await sandbox.run(
      buildImplementationPhaseOptions(agent, issue.number, issue.title),
    );
    if (implementation.commits.length === 0) {
      throw new Error(`Issue #${issue.number} produced no implementation commit.`);
    }
    if (!implementation.completionSignal) {
      throw new Error(
        `Issue #${issue.number} implementation did not emit its completion signal.`,
      );
    }

    const review = await sandbox.run(
      buildReviewPhaseOptions(agent, issue.number, branch),
    );
    if (!review.completionSignal) {
      throw new Error(
        `Issue #${issue.number} review did not emit its completion signal.`,
      );
    }

    console.log(`Running independent full PowerShell test gate for #${issue.number}...`);
    await runCommandAsync(
      "pwsh",
      ["-NoLogo", "-NoProfile", "-File", "./tests/Run-Tests.ps1"],
      { cwd: sandbox.worktreePath, stream: true },
    );

    assertCleanDeliverable(sandbox.worktreePath, branch);
    return { issue, branch, sandbox };
  } catch (error) {
    await closeSandbox(sandbox);
    throw error;
  }
}

async function integrateLatestBase(
  prepared: Awaited<ReturnType<typeof prepareIssue>>,
): Promise<string> {
  const { issue, branch, sandbox } = prepared;
  refreshBase();
  const containsLatestBase = runCommand(
    "git",
    ["merge-base", "--is-ancestor", BASE_REF, "HEAD"],
    { cwd: sandbox.worktreePath, allowFailure: true },
  ).exitCode === 0;

  if (!containsLatestBase) {
    console.log(
      `Main advanced while #${issue.number} was running; integrating ${BASE_REF}...`,
    );
    const merge = runCommand(
      "git",
      ["merge", "--no-edit", BASE_REF],
      { cwd: sandbox.worktreePath, stream: true, allowFailure: true },
    );
    if (merge.exitCode !== 0) {
      const mergeInProgress = runCommand(
        "git",
        ["rev-parse", "--quiet", "--verify", "MERGE_HEAD"],
        { cwd: sandbox.worktreePath, allowFailure: true },
      ).exitCode === 0;
      if (!mergeInProgress) {
        throw new Error(
          `Unable to integrate ${BASE_REF} into ${branch}; no resolvable merge was left in progress.`,
        );
      }

      const integration = await sandbox.run(
        buildIntegrationPhaseOptions(agent, issue.number, branch),
      );
      if (!integration.completionSignal) {
        throw new Error(
          `Issue #${issue.number} integration did not emit its completion signal.`,
        );
      }
    }

    console.log(
      `Running post-integration full PowerShell test gate for #${issue.number}...`,
    );
    await runCommandAsync(
      "pwsh",
      ["-NoLogo", "-NoProfile", "-File", "./tests/Run-Tests.ps1"],
      { cwd: sandbox.worktreePath, stream: true },
    );
    assertCleanDeliverable(sandbox.worktreePath, branch);
  }

  return runCommand(
    "git",
    ["rev-parse", "HEAD"],
    { cwd: sandbox.worktreePath },
  ).stdout;
}

async function deliverIssue(
  prepared: Awaited<ReturnType<typeof prepareIssue>>,
): Promise<void> {
  const { issue, branch, sandbox } = prepared;
  let headSha = "";
  try {
    headSha = await integrateLatestBase(prepared);
  } finally {
    await closeSandbox(sandbox);
  }

  const pullRequest = pushAndCreatePullRequest(issue, branch);
  console.log(`Created pull request #${pullRequest.number}: ${pullRequest.url}`);
  await waitForPullRequestChecks(pullRequest.url);
  mergePullRequest(pullRequest.url, headSha);
  ensureIssueClosed(issue.number, pullRequest.url);
  syncLocalMain();
  console.log(`Issue #${issue.number} delivered and closed.`);
}

async function claimBatch(issues: readonly GitHubIssue[]): Promise<void> {
  const claimed: GitHubIssue[] = [];
  try {
    for (const issue of issues) {
      console.log(`Claiming #${issue.number}: ${issue.title}`);
      claimIssue(issue);
      claimed.push(issue);
    }
  } catch (error) {
    for (const issue of claimed) {
      releaseIssueClaim(issue.number);
    }
    throw error;
  }
}

async function run(): Promise<void> {
  console.log("Running Sandcastle preflight...");
  assertAuthentication();
  assertHostReady();
  console.log(`Frontier concurrency: up to ${maxParallel} issue(s).`);

  let attemptedIssues = 0;
  let batch = 0;
  while (attemptedIssues < maxIterations) {
    batch += 1;
    console.log(`\n=== Batch ${batch}; ${attemptedIssues}/${maxIterations} issues attempted ===\n`);
    refreshBase();
    const remaining = maxIterations - attemptedIssues;
    const issues = selectNextIssues(
      listEligibleIssues(),
      Math.min(maxParallel, remaining),
    );
    if (issues.length === 0) {
      console.log("No unassigned, unblocked ready-for-agent issues remain.");
      return;
    }

    await claimBatch(issues);
    attemptedIssues += issues.length;

    const deliverSerially = createSerializedExecutor();
    const lanes = await Promise.allSettled(
      issues.map(async (issue) => {
        let prepared: Awaited<ReturnType<typeof prepareIssue>>;
        try {
          prepared = await prepareIssue(issue);
        } catch (error) {
          throw new Error(`Issue #${issue.number} preparation failed.`, {
            cause: error,
          });
        }

        try {
          await deliverSerially(() => deliverIssue(prepared));
        } catch (error) {
          throw new Error(`Issue #${issue.number} delivery failed.`, {
            cause: error,
          });
        }
      }),
    );

    const failures = lanes
      .filter((result): result is PromiseRejectedResult => result.status === "rejected")
      .map((result) => result.reason);

    if (failures.length > 0) {
      throw new AggregateError(
        failures,
        `${failures.length} issue lane(s) stopped safely.`,
      );
    }
  }
}

function formatError(error: unknown): string {
  if (error instanceof AggregateError) {
    const nested = [...error.errors]
      .map((entry, index) => `\n[${index + 1}] ${formatError(entry)}`)
      .join("");
    return `${error.stack || error.message}${nested}`;
  }
  if (error instanceof Error) {
    const cause = error.cause === undefined ? "" : `\nCaused by: ${formatError(error.cause)}`;
    return `${error.stack || error.message}${cause}`;
  }
  return String(error);
}

run().catch((error: unknown) => {
  const message = formatError(error);
  console.error(`\nSandcastle stopped safely:\n${message}`);
  console.error(
    "Affected issues remain assigned. Any created branch, worktree, or pull request is preserved for inspection.",
  );
  process.exitCode = 1;
});
