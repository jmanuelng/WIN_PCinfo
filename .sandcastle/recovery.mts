import {
  runCommand,
  type CommandResult,
  type WorkflowCommandAdapter,
} from "./workflow.mts";

export interface LaneRecovery {
  readonly issueNumber: number;
  readonly branch: string;
  worktreePath: string | null;
  worktreeDisposition:
    | "not-created"
    | "active"
    | "removed"
    | "preserved"
    | "unknown";
  localBranch: unknown;
  remoteBranch: unknown;
  pullRequest: unknown;
  issue: unknown;
  localMain: unknown;
  remoteMain: unknown;
  mainSynced: unknown;
}

type RecoveryCommands = Pick<WorkflowCommandAdapter, "run">;
const DEFAULT_RECOVERY_COMMANDS: RecoveryCommands = { run: runCommand };

export function createLaneRecovery(
  issueNumber: number,
  branch: string,
): LaneRecovery {
  return {
    issueNumber,
    branch,
    worktreePath: null,
    worktreeDisposition: "not-created",
    localBranch: "not-reconciled",
    remoteBranch: "not-reconciled",
    pullRequest: "not-reconciled",
    issue: "not-reconciled",
    localMain: "not-reconciled",
    remoteMain: "not-reconciled",
    mainSynced: "not-reconciled",
  };
}

function captureCommand(
  commands: RecoveryCommands,
  command: string,
  args: readonly string[],
) {
  try {
    return commands.run(command, args, { allowFailure: true });
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function isCommandResult(value: unknown): value is CommandResult {
  return (
    typeof value === "object" &&
    value !== null &&
    "stdout" in value &&
    "stderr" in value &&
    "exitCode" in value
  );
}

function parseCapturedJson(value: unknown): unknown {
  if (!isCommandResult(value) || value.exitCode !== 0) {
    return value;
  }
  try {
    return JSON.parse(value.stdout);
  } catch (error) {
    return {
      ...value,
      parseError: error instanceof Error ? error.message : String(error),
    };
  }
}

export function reconcileLaneRecovery(
  recovery: LaneRecovery,
  commands: RecoveryCommands = DEFAULT_RECOVERY_COMMANDS,
): void {
  const worktrees = captureCommand(commands, "git", [
    "worktree",
    "list",
    "--porcelain",
  ]);
  if (
    isCommandResult(worktrees) &&
    recovery.worktreeDisposition === "not-created"
  ) {
    const block = worktrees.stdout
      .split(/\r?\n\r?\n/)
      .find((entry) => entry.includes(`branch refs/heads/${recovery.branch}`));
    const pathLine = block
      ?.split(/\r?\n/)
      .find((line) => line.startsWith("worktree "));
    if (pathLine) {
      recovery.worktreePath = pathLine.slice("worktree ".length);
      recovery.worktreeDisposition = "active";
    }
  }

  recovery.localBranch = captureCommand(commands, "git", [
    "show-ref",
    "--verify",
    `refs/heads/${recovery.branch}`,
  ]);
  recovery.remoteBranch = captureCommand(commands, "git", [
    "ls-remote",
    "--exit-code",
    "--heads",
    "origin",
    recovery.branch,
  ]);
  recovery.pullRequest = parseCapturedJson(
    captureCommand(commands, "gh", [
      "pr",
      "view",
      recovery.branch,
      "--json",
      "number,url,state,mergedAt,headRefOid",
    ]),
  );
  recovery.issue = parseCapturedJson(
    captureCommand(commands, "gh", [
      "issue",
      "view",
      String(recovery.issueNumber),
      "--json",
      "number,state,assignees,url",
    ]),
  );
  recovery.localMain = captureCommand(commands, "git", [
    "rev-parse",
    "refs/heads/main",
  ]);
  recovery.remoteMain = captureCommand(commands, "git", [
    "rev-parse",
    "refs/remotes/origin/main",
  ]);
  recovery.mainSynced =
    isCommandResult(recovery.localMain) &&
    isCommandResult(recovery.remoteMain) &&
    recovery.localMain.exitCode === 0 &&
    recovery.remoteMain.exitCode === 0
      ? recovery.localMain.stdout === recovery.remoteMain.stdout
      : "unknown";
}

export function laneFailure(
  phase: "preparation" | "delivery",
  recovery: LaneRecovery,
  cause: unknown,
  commands: RecoveryCommands = DEFAULT_RECOVERY_COMMANDS,
): Error {
  reconcileLaneRecovery(recovery, commands);
  return new Error(
    `Issue #${recovery.issueNumber} ${phase} failed. Recovery state:\n${JSON.stringify(recovery, null, 2)}`,
    { cause },
  );
}
