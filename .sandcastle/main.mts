import * as sandcastle from "@ai-hero/sandcastle";
import { noSandbox } from "@ai-hero/sandcastle/sandboxes/no-sandbox";
import {
  BASE_REF,
  assertAuthentication,
  assertHostReady,
  claimIssue,
  ensureIssueClosed,
  listEligibleIssues,
  mergePullRequest,
  parseMaxIterations,
  pushAndCreatePullRequest,
  refreshBase,
  runCommand,
  selectNextIssue,
  syncLocalMain,
  waitForPullRequestChecks,
} from "./workflow.mts";
import { createCodexAgent } from "./codex-agent.mts";

const maxIterations = parseMaxIterations(process.argv.slice(2));
const agent = createCodexAgent();

async function run(): Promise<void> {
  console.log("Running Sandcastle preflight...");
  assertAuthentication();
  assertHostReady();

  for (let iteration = 1; iteration <= maxIterations; iteration++) {
    console.log(`\n=== Iteration ${iteration}/${maxIterations} ===\n`);
    refreshBase();
    const issue = selectNextIssue(listEligibleIssues());
    if (!issue) {
      console.log("No unassigned, unblocked ready-for-agent issues remain.");
      return;
    }

    console.log(`Claiming #${issue.number}: ${issue.title}`);
    claimIssue(issue);

    const branch = `sandcastle/issue-${issue.number}-${Date.now()}`;
    const sandbox = await sandcastle.createSandbox({
      branch,
      baseBranch: BASE_REF,
      sandbox: noSandbox(),
    });

    let headSha = "";
    try {
      const implementation = await sandbox.run({
        name: `issue-${issue.number}-implementer`,
        maxIterations: 1,
        agent,
        promptFile: "./.sandcastle/implement-prompt.md",
        promptArgs: {
          ISSUE_NUMBER: issue.number,
          ISSUE_TITLE: issue.title,
        },
      });
      if (implementation.commits.length === 0) {
        throw new Error(
          `Issue #${issue.number} produced no implementation commit.`,
        );
      }
      if (!implementation.completionSignal) {
        throw new Error(
          `Issue #${issue.number} implementation did not emit its completion signal.`,
        );
      }

      const review = await sandbox.run({
        name: `issue-${issue.number}-reviewer`,
        maxIterations: 1,
        agent,
        promptFile: "./.sandcastle/review-prompt.md",
        promptArgs: {
          ISSUE_NUMBER: issue.number,
          BRANCH: branch,
          BASE_BRANCH: BASE_REF,
        },
      });
      if (!review.completionSignal) {
        throw new Error(
          `Issue #${issue.number} review did not emit its completion signal.`,
        );
      }

      console.log("Running independent full PowerShell test gate...");
      runCommand(
        "pwsh",
        ["-NoLogo", "-NoProfile", "-File", "./tests/Run-Tests.ps1"],
        { cwd: sandbox.worktreePath, stream: true },
      );

      const dirty = runCommand(
        "git",
        ["status", "--porcelain"],
        { cwd: sandbox.worktreePath },
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
          { cwd: sandbox.worktreePath },
        ).stdout,
        10,
      );
      if (!Number.isInteger(ahead) || ahead < 1) {
        throw new Error(`Branch ${branch} contains no deliverable commits.`);
      }
      headSha = runCommand(
        "git",
        ["rev-parse", "HEAD"],
        { cwd: sandbox.worktreePath },
      ).stdout;
    } finally {
      const closeResult = await sandbox.close();
      if (closeResult.preservedWorktreePath) {
        console.error(
          `Sandcastle preserved a dirty worktree at ${closeResult.preservedWorktreePath}`,
        );
      }
    }

    const pullRequest = pushAndCreatePullRequest(issue, branch);
    console.log(`Created pull request #${pullRequest.number}: ${pullRequest.url}`);
    await waitForPullRequestChecks(pullRequest.url);
    mergePullRequest(pullRequest.url, headSha);
    ensureIssueClosed(issue.number, pullRequest.url);
    syncLocalMain();
    console.log(`Issue #${issue.number} delivered and closed.`);
  }
}

run().catch((error: unknown) => {
  const message = error instanceof Error ? error.stack || error.message : String(error);
  console.error(`\nSandcastle stopped safely:\n${message}`);
  console.error(
    "The current issue remains assigned. Any created branch, worktree, or pull request is preserved for inspection.",
  );
  process.exitCode = 1;
});
