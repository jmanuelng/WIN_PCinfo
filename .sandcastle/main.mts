import * as sandcastle from "@ai-hero/sandcastle";
import { noSandbox } from "@ai-hero/sandcastle/sandboxes/no-sandbox";
import {
  BASE_REF,
  assertAuthentication,
  assertHostReady,
  buildImplementationPhaseOptions,
  buildIntegrationPhaseOptions,
  buildReviewPhaseOptions,
  authenticatedGitHubLogin,
  claimIssue,
  createSerializedExecutor,
  ensureIssueClosed,
  isSafelyClaimedIssue,
  listLocalIssueLanes,
  listReadyIssues,
  loadIssue,
  mergePullRequest,
  parseIssueNumber,
  parseMaxIterations,
  parseMaxParallel,
  pushAndCreatePullRequest,
  refreshBase,
  releaseIssueClaim,
  releaseOrphanSelfClaims,
  readLatestPhaseLog,
  recordPhaseSuccess,
  removeWorktreeTeardownTargets,
  requireStartableIssue,
  resultHasCompletionSignal,
  runCommand,
  runCommandAsync,
  runWithRequiredCleanup,
  selectStartableIssues,
  syncLocalMain,
  waitForPullRequestChecks,
  withAgentHeartbeat,
  phaseCompletedSuccessfully,
  SANDBOX_SETUP_TIMEOUT_MS,
  SandboxSetupTimeoutError,
  type GitHubIssue,
  type LocalIssueLane,
} from "./workflow.mts";
import { createGrokAgent, isExhaustedGrokAuthError } from "./grok-agent.mts";
import { grokLoginReminder, readGrokAccessSnapshot } from "./grok-auth.mts";
import {
  createLaneRecovery,
  laneFailure,
  type LaneRecovery,
} from "./recovery.mts";

const cliArgs = process.argv.slice(2);
const maxIterations = parseMaxIterations(cliArgs);
const maxParallel = parseMaxParallel(cliArgs);
const requestedIssueNumber = parseIssueNumber(cliArgs);
const agent = createGrokAgent();

function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  onTimeout: () => Error,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(onTimeout());
    }, timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function closeSandbox(
  sandbox: Awaited<ReturnType<typeof sandcastle.createSandbox>>,
  recovery: LaneRecovery,
): Promise<void> {
  recovery.worktreePath = sandbox.worktreePath;
  removeWorktreeTeardownTargets(sandbox.worktreePath);
  let closeResult: Awaited<ReturnType<typeof sandbox.close>>;
  try {
    closeResult = await sandbox.close();
  } catch (error) {
    recovery.worktreeDisposition = "unknown";
    throw error;
  }
  if (closeResult.preservedWorktreePath) {
    recovery.worktreeDisposition = "preserved";
    recovery.worktreePath = closeResult.preservedWorktreePath;
    console.error(
      `Sandcastle preserved a dirty worktree at ${closeResult.preservedWorktreePath}`,
    );
  } else {
    recovery.worktreeDisposition = "removed";
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

function localLaneForIssue(
  issueNumber: number,
  lanes: readonly LocalIssueLane[],
): LocalIssueLane | undefined {
  return lanes.find((lane) => lane.issueNumber === issueNumber);
}

function branchAheadOfBase(worktreePath: string): number {
  const ahead = Number.parseInt(
    runCommand(
      "git",
      ["rev-list", "--count", `${BASE_REF}..HEAD`],
      { cwd: worktreePath },
    ).stdout,
    10,
  );
  return Number.isInteger(ahead) ? ahead : 0;
}

async function createIssueSandbox(
  issue: GitHubIssue,
  branch: string,
  recovery: LaneRecovery,
) {
  try {
    const sandbox = await withTimeout(
      sandcastle.createSandbox({
        branch,
        baseBranch: BASE_REF,
        sandbox: noSandbox(),
      }),
      SANDBOX_SETUP_TIMEOUT_MS,
      () => new SandboxSetupTimeoutError(issue.number),
    );
    recovery.worktreePath = sandbox.worktreePath;
    recovery.worktreeDisposition = "active";
    return sandbox;
  } catch (error) {
    if (error instanceof SandboxSetupTimeoutError) {
      try {
        releaseIssueClaim(issue.number);
      } catch (releaseError) {
        throw new AggregateError(
          [error, releaseError],
          `Sandbox setup timed out for #${issue.number} and the claim could not be released.`,
        );
      }
    }
    throw error;
  }
}

async function prepareIssue(
  issue: GitHubIssue,
  recovery: LaneRecovery,
  resume: boolean,
) {
  const branch = recovery.branch;
  // This host has no container boundary. Agents run on the dedicated Windows
  // machine because the product suite is PowerShell.
  const sandbox = await createIssueSandbox(issue, branch, recovery);

  try {
    const implementerDone =
      resume &&
      phaseCompletedSuccessfully(issue.number, "implementer") &&
      branchAheadOfBase(sandbox.worktreePath) >= 1;
    if (implementerDone) {
      console.log(
        `Resuming #${issue.number}: implementer already completed on ${branch}.`,
      );
    } else {
      const implementation = await withAgentHeartbeat(
        issue.number,
        "implementer",
        () =>
          sandbox.run(
            buildImplementationPhaseOptions(agent, issue.number, issue.title),
          ),
      );
      if (implementation.commits.length === 0) {
        throw new Error(`Issue #${issue.number} produced no implementation commit.`);
      }
      if (
        !resultHasCompletionSignal({
          ...implementation,
          phaseLog: readLatestPhaseLog(issue.number, "implementer"),
        })
      ) {
        throw new Error(
          `Issue #${issue.number} implementation did not emit its completion signal.`,
        );
      }
      recordPhaseSuccess(issue.number, "implementer");
    }

    const reviewerDone =
      resume && phaseCompletedSuccessfully(issue.number, "reviewer");
    if (reviewerDone) {
      console.log(
        `Resuming #${issue.number}: reviewer already completed on ${branch}.`,
      );
    } else {
      const review = await withAgentHeartbeat(issue.number, "reviewer", () =>
        sandbox.run(buildReviewPhaseOptions(agent, issue.number, branch)),
      );
      if (
        !resultHasCompletionSignal({
          ...review,
          phaseLog: readLatestPhaseLog(issue.number, "reviewer"),
        })
      ) {
        throw new Error(
          `Issue #${issue.number} review did not emit its completion signal.`,
        );
      }
      recordPhaseSuccess(issue.number, "reviewer");
    }

    console.log(`Running independent full PowerShell test gate for #${issue.number}...`);
    await runCommandAsync(
      "pwsh",
      ["-NoLogo", "-NoProfile", "-File", "./tests/Run-Tests.ps1"],
      { cwd: sandbox.worktreePath, stream: true },
    );

    assertCleanDeliverable(sandbox.worktreePath, branch);
    return { issue, branch, sandbox, recovery, closed: false };
  } catch (error) {
    try {
      await closeSandbox(sandbox, recovery);
    } catch (closeError) {
      throw new AggregateError(
        [error, closeError],
        `Issue #${issue.number} preparation and sandbox cleanup both failed.`,
      );
    }
    throw error;
  }
}

async function closePreparedIssue(
  prepared: Awaited<ReturnType<typeof prepareIssue>>,
): Promise<void> {
  if (prepared.closed) {
    return;
  }
  await closeSandbox(prepared.sandbox, prepared.recovery);
  prepared.closed = true;
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

      const integration = await withAgentHeartbeat(
        issue.number,
        "integrator",
        () =>
          sandbox.run(
            buildIntegrationPhaseOptions(agent, issue.number, branch),
          ),
      );
      if (
        !resultHasCompletionSignal({
          ...integration,
          phaseLog: readLatestPhaseLog(issue.number, "integrator"),
        })
      ) {
        throw new Error(
          `Issue #${issue.number} integration did not emit its completion signal.`,
        );
      }
      recordPhaseSuccess(issue.number, "integrator");
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
  const { issue, branch } = prepared;
  const headSha = await runWithRequiredCleanup(
    () => integrateLatestBase(prepared),
    () => closePreparedIssue(prepared),
  );

  const pullRequest = pushAndCreatePullRequest(issue, branch);
  console.log(`Created pull request #${pullRequest.number}: ${pullRequest.url}`);
  await waitForPullRequestChecks(pullRequest.url);
  mergePullRequest(pullRequest.url, headSha);
  ensureIssueClosed(issue.number, pullRequest.url);
  syncLocalMain();
  console.log(`Issue #${issue.number} delivered and closed.`);
}

async function claimBatch(
  issues: readonly GitHubIssue[],
  viewer: string,
): Promise<void> {
  const claimed: GitHubIssue[] = [];
  try {
    for (const issue of issues) {
      const current = loadIssue(issue.number);
      if (isSafelyClaimedIssue(current, viewer)) {
        console.log(`Resuming claimed #${issue.number}: ${issue.title}`);
        continue;
      }
      console.log(`Claiming #${issue.number}: ${issue.title}`);
      claimIssue(issue);
      claimed.push(issue);
    }
  } catch (error) {
    const rollbackFailures: unknown[] = [];
    for (const issue of claimed) {
      try {
        releaseIssueClaim(issue.number);
        console.error(`Released verified claim for #${issue.number}.`);
      } catch (rollbackError) {
        rollbackFailures.push(
          new Error(`Issue #${issue.number} claim rollback failed.`, {
            cause: rollbackError,
          }),
        );
      }
    }
    if (rollbackFailures.length > 0) {
      throw new AggregateError(
        [error, ...rollbackFailures],
        "Batch claim failed and one or more earlier claim rollbacks could not be verified.",
      );
    }
    throw error;
  }
}

async function run(): Promise<void> {
  console.log("Running Sandcastle preflight...");
  assertAuthentication();
  assertHostReady();
  console.log(`Frontier concurrency: up to ${maxParallel} issue(s).`);
  if (requestedIssueNumber !== undefined) {
    console.log(`Pinned issue: #${requestedIssueNumber}.`);
  }

  let attemptedIssues = 0;
  let batch = 0;
  while (attemptedIssues < maxIterations) {
    batch += 1;
    console.log(`\n=== Batch ${batch}; ${attemptedIssues}/${maxIterations} issues attempted ===\n`);
    refreshBase();
    const remaining = maxIterations - attemptedIssues;
    const desiredBatchSize = Math.min(maxParallel, remaining);
    const viewer = authenticatedGitHubLogin();
    const localLanes = listLocalIssueLanes();
    const readyIssues = listReadyIssues();
    const released = releaseOrphanSelfClaims(readyIssues, viewer, localLanes);
    for (const issueNumber of released) {
      console.log(
        `Released orphan self-claim for #${issueNumber} (no local worktree).`,
      );
    }
    const startableLanes = listLocalIssueLanes();
    const startableReady = released.length > 0 ? listReadyIssues() : readyIssues;
    const issues =
      requestedIssueNumber === undefined
        ? selectStartableIssues(
            startableReady,
            viewer,
            startableLanes,
            desiredBatchSize,
          )
        : attemptedIssues === 0
          ? [
              requireStartableIssue(
                requestedIssueNumber,
                viewer,
                startableLanes,
              ),
            ]
          : [];
    if (issues.length === 0) {
      console.log("No unassigned, unblocked ready-for-agent issues remain.");
      return;
    }

    await claimBatch(issues, viewer);
    attemptedIssues += issues.length;

    const delivery = createSerializedExecutor();
    const lanes = await Promise.allSettled(
      issues.map(async (issue) => {
        const existing = localLaneForIssue(issue.number, startableLanes);
        const recovery = createLaneRecovery(
          issue.number,
          existing?.branch ?? `sandcastle/issue-${issue.number}-${Date.now()}`,
        );
        let prepared: Awaited<ReturnType<typeof prepareIssue>>;
        try {
          prepared = await prepareIssue(issue, recovery, Boolean(existing));
        } catch (error) {
          if (error instanceof SandboxSetupTimeoutError) {
            console.error(error.message);
            return;
          }
          delivery.stop(error);
          throw laneFailure("preparation", recovery, error);
        }

        try {
          await delivery.execute(() => deliverIssue(prepared));
        } catch (error) {
          let failure = error;
          try {
            await closePreparedIssue(prepared);
          } catch (closeError) {
            failure = new AggregateError(
              [error, closeError],
              `Issue #${issue.number} delivery and sandbox cleanup both failed.`,
            );
          }
          throw laneFailure("delivery", recovery, failure);
        }
      }),
    );

    const failures = lanes
      .filter((result): result is PromiseRejectedResult => result.status === "rejected")
      .map((result) => result.reason);

    if (failures.length > 0) {
      const aggregate = new AggregateError(
        failures,
        `${failures.length} issue lane(s) stopped safely.`,
      );
      if (isExhaustedGrokAuthError(aggregate)) {
        console.error(grokLoginReminder(readGrokAccessSnapshot()));
      }
      throw aggregate;
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
    "Inspect the per-lane errors above for exact claim and artifact recovery state.",
  );
  process.exitCode = 1;
});
