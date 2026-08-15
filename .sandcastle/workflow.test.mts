import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createCodexAgent } from "./codex-agent.mts";
import {
  createLaneRecovery,
  laneFailure,
  reconcileLaneRecovery,
} from "./recovery.mts";
import {
  AGENT_PHASE_IDLE_TIMEOUT_SECONDS,
  DEFAULT_MAX_PARALLEL_ISSUES,
  analyzeChecks,
  buildImplementationPhaseOptions,
  buildIntegrationPhaseOptions,
  buildReviewPhaseOptions,
  createSerializedExecutor,
  isSafelyClaimedIssue,
  parseMaxIterations,
  parseMaxParallel,
  listEligibleIssues,
  releaseIssueClaim,
  runCommandAsync,
  runWithRequiredCleanup,
  selectNextIssue,
  selectNextIssues,
  type CommandResult,
  type GitHubIssue,
  type WorkflowCommandAdapter,
} from "./workflow.mts";

function commandResult(stdout = ""): CommandResult {
  return { stdout, stderr: "", exitCode: 0 };
}

function failedCommand(stderr: string): CommandResult {
  return { stdout: "", stderr, exitCode: 1 };
}

function recoveryCommands(options: {
  readonly pullRequest: unknown | null;
  readonly issue: unknown;
  readonly localMain: string;
  readonly remoteMain: string;
}) {
  return {
    run(command: string, args: readonly string[]): CommandResult {
      if (command === "gh" && args[0] === "pr") {
        return options.pullRequest === null
          ? failedCommand("no pull request")
          : commandResult(JSON.stringify(options.pullRequest));
      }
      if (command === "gh" && args[0] === "issue") {
        return commandResult(JSON.stringify(options.issue));
      }
      if (command === "git" && args[0] === "worktree") {
        return commandResult("");
      }
      if (command === "git" && args[0] === "show-ref") {
        return commandResult("branch-sha refs/heads/test-branch");
      }
      if (command === "git" && args[0] === "ls-remote") {
        if (args.at(-1) === "refs/heads/main") {
          return commandResult(
            `${options.remoteMain}\trefs/heads/main`,
          );
        }
        return failedCommand("remote branch absent");
      }
      if (command === "git" && args.at(-1) === "refs/heads/main") {
        return commandResult(options.localMain);
      }
      throw new Error(`Unexpected recovery command: ${command} ${args.join(" ")}`);
    },
  };
}

function issue(
  number: number,
  overrides: Partial<GitHubIssue> = {},
): GitHubIssue {
  return {
    number,
    title: `Issue ${number}`,
    state: "OPEN",
    labels: [{ name: "ready-for-agent" }],
    assignees: [],
    blockedBy: { nodes: [] },
    subIssuesSummary: { completed: 0, percentCompleted: 0, total: 0 },
    ...overrides,
  };
}

function frontierNode(
  number: number,
  overrides: Record<string, unknown> = {},
) {
  return {
    number,
    title: `Issue ${number}`,
    state: "OPEN",
    url: `https://example.test/issues/${number}`,
    labels: { nodes: [{ name: "ready-for-agent" }] },
    assignees: { nodes: [] },
    blockedBy: { nodes: [], totalCount: 0 },
    subIssuesSummary: { completed: 0, percentCompleted: 0, total: 0 },
    ...overrides,
  };
}

test("selectNextIssue chooses the oldest eligible frontier issue", () => {
  const selected = selectNextIssue([
    issue(9),
    issue(4),
    issue(2, { assignees: [{ login: "someone" }] }),
    issue(3, { blockedBy: { nodes: [{ number: 1 }] } }),
    issue(1, { labels: [{ name: "needs-triage" }] }),
  ]);

  assert.equal(selected?.number, 4);
});

test("selectNextIssues returns a bounded oldest-first frontier batch", () => {
  assert.deepEqual(
    selectNextIssues([
      issue(9),
      issue(4),
      issue(7, { assignees: [{ login: "someone" }] }),
      issue(6),
    ], 2).map(({ number }) => number),
    [4, 6],
  );
  assert.throws(() => selectNextIssues([issue(1)], 0), /positive integer/);
});

test("selectNextIssue accepts array-shaped blockedBy data", () => {
  assert.equal(selectNextIssue([issue(2, { blockedBy: [] })])?.number, 2);
  assert.equal(
    selectNextIssue([issue(2, { blockedBy: [{ number: 1 }] })]),
    undefined,
  );
});

test("selectNextIssue ignores closed historical blockers", () => {
  const selected = selectNextIssue([
    issue(54, {
      blockedBy: {
        nodes: [
          { number: 53, state: "CLOSED" },
          { number: 44, state: "CLOSED" },
        ],
      },
    }),
  ]);

  assert.equal(selected?.number, 54);
  assert.equal(
    selectNextIssue([
      issue(55, {
        blockedBy: [{ number: 54, state: "closed" }],
      }),
    ])?.number,
    55,
  );
});

test("selectNextIssue treats open or unrecognized dependencies as blockers", () => {
  assert.equal(
    selectNextIssue([
      issue(55, {
        blockedBy: { nodes: [{ number: 54, state: "OPEN" }] },
      }),
    ]),
    undefined,
  );
  assert.equal(
    selectNextIssue([
      issue(55, {
        blockedBy: { nodes: [{ number: 54, state: "UNKNOWN" }] },
      }),
    ]),
    undefined,
  );
  assert.equal(
    selectNextIssue([
      issue(55, {
        blockedBy: {
          nodes: [{ number: 54, state: "CLOSED" }],
          totalCount: 2,
        },
      }),
    ]),
    undefined,
  );
});

test("selectNextIssue excludes parent specifications with open child issues", () => {
  const parentSpecification = issue(37, {
    subIssuesSummary: {
      completed: 22,
      percentCompleted: 57,
      total: 38,
    },
  });

  assert.equal(selectNextIssue([parentSpecification]), undefined);
  assert.equal(
    selectNextIssue([issue(38, { subIssuesSummary: undefined })]),
    undefined,
  );
  assert.equal(
    selectNextIssue([
      issue(39, {
        subIssuesSummary: {
          completed: 38,
          percentCompleted: 100,
          total: 38,
        },
      }),
    ])?.number,
    39,
  );
});

test("analyzeChecks fails closed and separates terminal states", () => {
  const summary = analyzeChecks([
    { name: "build", status: "COMPLETED", conclusion: "SUCCESS" },
    { name: "security", status: "COMPLETED", conclusion: "FAILURE" },
    { context: "policy", state: "PENDING" },
    { name: "mystery", status: "COMPLETED", conclusion: null },
  ]);

  assert.deepEqual(summary.passed, ["build"]);
  assert.deepEqual(summary.failed, [
    "security",
    "mystery (completed without a conclusion)",
  ]);
  assert.deepEqual(summary.pending, ["policy"]);
});

test("parseMaxIterations defaults to the AFK run and caps autonomy", () => {
  assert.equal(parseMaxIterations([]), 10);
  assert.equal(parseMaxIterations(["--max-iterations", "10"]), 10);
  assert.throws(
    () => parseMaxIterations(["--max-iterations", "11"]),
    /integer from 1 through 10/,
  );
});

test("verified claims recheck every mutable eligibility condition", () => {
  const claimed = issue(57, { assignees: [{ login: "agent" }] });
  assert.equal(isSafelyClaimedIssue(claimed, "agent"), true);
  assert.equal(
    isSafelyClaimedIssue(
      { ...claimed, labels: [{ name: "needs-triage" }] },
      "agent",
    ),
    false,
  );
  assert.equal(
    isSafelyClaimedIssue(
      { ...claimed, blockedBy: { nodes: [{ state: "OPEN" }] } },
      "agent",
    ),
    false,
  );
  assert.equal(
    isSafelyClaimedIssue({ ...claimed, state: "CLOSED" }, "agent"),
    false,
  );
});

test("frontier discovery paginates until it finds two eligible issues", () => {
  const cursors: string[] = [];
  const pages = [
    {
      data: {
        repository: {
          issues: {
            nodes: [
              frontierNode(1, {
                assignees: { nodes: [{ login: "someone" }] },
              }),
            ],
            pageInfo: { hasNextPage: true, endCursor: "cursor-1" },
          },
        },
      },
    },
    {
      data: {
        repository: {
          issues: {
            nodes: [frontierNode(2), frontierNode(3)],
            pageInfo: { hasNextPage: false, endCursor: null },
          },
        },
      },
    },
  ];
  const commands: WorkflowCommandAdapter = {
    run: () => commandResult("owner/repository"),
    json<T>(_command: string, args: readonly string[]) {
      const cursor = args.find((arg) => arg.startsWith("cursor="));
      if (cursor) cursors.push(cursor);
      return pages.shift() as T;
    },
  };

  const selected = selectNextIssues(listEligibleIssues(2, commands), 2);
  assert.deepEqual(selected.map(({ number }) => number), [2, 3]);
  assert.deepEqual(cursors, ["cursor=cursor-1"]);
  assert.equal(pages.length, 0);
});

test("frontier discovery fails closed on missing cursors or command errors", () => {
  const missingCursor: WorkflowCommandAdapter = {
    run: () => commandResult("owner/repository"),
    json<T>() {
      return {
        data: {
          repository: {
            issues: {
              nodes: [],
              pageInfo: { hasNextPage: true, endCursor: null },
            },
          },
        },
      } as T;
    },
  };
  assert.throws(
    () => listEligibleIssues(2, missingCursor),
    /omitted its next cursor/,
  );

  const commandFailure: WorkflowCommandAdapter = {
    run: () => commandResult("owner/repository"),
    json<T>(): T {
      throw new Error("expected GraphQL failure");
    },
  };
  assert.throws(
    () => listEligibleIssues(2, commandFailure),
    /expected GraphQL failure/,
  );
});

test("claim rollback verifies release and propagates failures", () => {
  const released: WorkflowCommandAdapter = {
    run: (_command, args) =>
      commandResult(args[0] === "api" ? "agent" : ""),
    json<T>() {
      return issue(57, { assignees: [] }) as T;
    },
  };
  assert.doesNotThrow(() => releaseIssueClaim(57, released));

  const stillAssigned: WorkflowCommandAdapter = {
    ...released,
    json<T>() {
      return issue(57, { assignees: [{ login: "agent" }] }) as T;
    },
  };
  assert.throws(
    () => releaseIssueClaim(57, stillAssigned),
    /rollback could not be verified/,
  );

  const editFailure: WorkflowCommandAdapter = {
    ...released,
    run: (_command, args) => {
      if (args[0] === "issue") throw new Error("expected edit failure");
      return commandResult("agent");
    },
  };
  assert.throws(
    () => releaseIssueClaim(57, editFailure),
    /expected edit failure/,
  );
});

test("stopped delivery reports its exact branch and removed worktree state", () => {
  const recovery = createLaneRecovery(58, "test-branch");
  recovery.worktreePath = "C:/worktrees/test-branch";
  recovery.worktreeDisposition = "removed";
  const error = laneFailure(
    "delivery",
    recovery,
    new Error("batch stopped"),
    recoveryCommands({
      pullRequest: null,
      issue: {
        number: 58,
        state: "OPEN",
        assignees: [{ login: "agent" }],
      },
      localMain: "same-sha",
      remoteMain: "same-sha",
    }),
  );

  assert.match(error.message, /"branch": "test-branch"/);
  assert.match(error.message, /"worktreeDisposition": "removed"/);
  assert.match(error.message, /"state": "OPEN"/);
  assert.match(error.message, /"mainSynced": true/);
  assert.match(error.message, /no pull request/);
});

test("post-merge failure reports merged PR, closed issue, and stale local main", () => {
  const recovery = createLaneRecovery(58, "test-branch");
  recovery.worktreeDisposition = "removed";
  const error = laneFailure(
    "delivery",
    recovery,
    new Error("local sync failed"),
    recoveryCommands({
      pullRequest: {
        number: 200,
        url: "https://example.test/pull/200",
        state: "MERGED",
        mergedAt: "2026-08-15T00:00:00Z",
        headRefOid: "head-sha",
      },
      issue: { number: 58, state: "CLOSED", assignees: [] },
      localMain: "old-sha",
      remoteMain: "new-sha",
    }),
  );

  assert.match(error.message, /"state": "MERGED"/);
  assert.match(error.message, /"state": "CLOSED"/);
  assert.match(error.message, /"mainSynced": false/);
});

test("unknown sandbox-close disposition reconciles present and absent worktrees", () => {
  const base = recoveryCommands({
    pullRequest: null,
    issue: { number: 58, state: "OPEN", assignees: [{ login: "agent" }] },
    localMain: "same-sha",
    remoteMain: "same-sha",
  });
  const present = createLaneRecovery(58, "test-branch");
  present.worktreeDisposition = "unknown";
  reconcileLaneRecovery(present, {
    run(command, args) {
      if (command === "git" && args[0] === "worktree") {
        return commandResult(
          "worktree C:/worktrees/test-branch\nHEAD branch-sha\nbranch refs/heads/test-branch\n",
        );
      }
      return base.run(command, args);
    },
  });
  assert.equal(present.worktreeDisposition, "active");
  assert.equal(present.worktreePath, "C:/worktrees/test-branch");

  const absent = createLaneRecovery(58, "test-branch");
  absent.worktreeDisposition = "unknown";
  reconcileLaneRecovery(absent, base);
  assert.equal(absent.worktreeDisposition, "removed");

  const prefixOnly = createLaneRecovery(58, "test-branch");
  prefixOnly.worktreeDisposition = "unknown";
  reconcileLaneRecovery(prefixOnly, {
    run(command, args) {
      if (command === "git" && args[0] === "worktree") {
        return commandResult(
          "worktree C:/worktrees/test-branch-longer\nHEAD branch-sha\nbranch refs/heads/test-branch-longer\n",
        );
      }
      return base.run(command, args);
    },
  });
  assert.equal(prefixOnly.worktreeDisposition, "removed");

  const queryFailed = createLaneRecovery(58, "test-branch");
  queryFailed.worktreeDisposition = "unknown";
  reconcileLaneRecovery(queryFailed, {
    run(command, args) {
      if (command === "git" && args[0] === "worktree") {
        return failedCommand("worktree enumeration failed");
      }
      return base.run(command, args);
    },
  });
  assert.equal(queryFailed.worktreeDisposition, "unknown");
});

test("parseMaxParallel defaults to two and enforces the host-safe cap", () => {
  assert.equal(DEFAULT_MAX_PARALLEL_ISSUES, 2);
  assert.equal(parseMaxParallel([]), 2);
  assert.equal(parseMaxParallel(["--max-parallel", "1"]), 1);
  assert.equal(parseMaxParallel(["--max-parallel", "2"]), 2);
  assert.throws(
    () => parseMaxParallel(["--max-parallel", "3"]),
    /integer from 1 through 2/,
  );
});

test("async command execution permits two long-running lanes to overlap", async () => {
  const barrierDirectory = mkdtempSync(join(tmpdir(), "sandcastle-parallel-"));
  const firstMarker = join(barrierDirectory, "first");
  const secondMarker = join(barrierDirectory, "second");
  const barrierScript = (ownMarker: string, peerMarker: string) => `
    const { existsSync, writeFileSync } = require("node:fs");
    writeFileSync(${JSON.stringify(ownMarker)}, "ready");
    const deadline = Date.now() + 5000;
    while (!existsSync(${JSON.stringify(peerMarker)}) && Date.now() < deadline) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    }
    if (!existsSync(${JSON.stringify(peerMarker)})) process.exit(2);
  `;

  try {
    await Promise.all([
      runCommandAsync(process.execPath, ["-e", barrierScript(firstMarker, secondMarker)]),
      runCommandAsync(process.execPath, ["-e", barrierScript(secondMarker, firstMarker)]),
    ]);
  } finally {
    rmSync(barrierDirectory, { force: true, recursive: true });
  }
});

test("serialized executor stops queued deliveries after the first failure", async () => {
  const executor = createSerializedExecutor();
  const events: string[] = [];
  const first = executor.execute(async () => {
    events.push("first:start");
    await new Promise((resolve) => setTimeout(resolve, 20));
    events.push("first:fail");
    throw new Error("expected failure");
  });
  const second = executor.execute(async () => {
    events.push("second:start");
    events.push("second:done");
    return 2;
  });

  await assert.rejects(first, /expected failure/);
  await assert.rejects(second, /stopped before this operation/);
  assert.deepEqual(events, ["first:start", "first:fail"]);
});

test("required cleanup preserves simultaneous operation and cleanup failures", async () => {
  const operationError = new Error("integration failed");
  const cleanupError = new Error("sandbox close failed");
  await assert.rejects(
    runWithRequiredCleanup(
      async () => {
        throw operationError;
      },
      async () => {
        throw cleanupError;
      },
    ),
    (error: unknown) => {
      assert.ok(error instanceof AggregateError);
      assert.deepEqual(error.errors, [operationError, cleanupError]);
      return true;
    },
  );
});

test("all agent phases tolerate the repository's long full-suite silence", () => {
  const agent = { kind: "test-agent" };
  const implementation = buildImplementationPhaseOptions(agent, 54, "MDM");
  const review = buildReviewPhaseOptions(agent, 54, "sandcastle/issue-54");
  const integration = buildIntegrationPhaseOptions(
    agent,
    54,
    "sandcastle/issue-54",
  );

  assert.equal(AGENT_PHASE_IDLE_TIMEOUT_SECONDS, 2 * 60 * 60);
  assert.equal(
    implementation.idleTimeoutSeconds,
    AGENT_PHASE_IDLE_TIMEOUT_SECONDS,
  );
  assert.equal(review.idleTimeoutSeconds, AGENT_PHASE_IDLE_TIMEOUT_SECONDS);
  assert.equal(integration.idleTimeoutSeconds, AGENT_PHASE_IDLE_TIMEOUT_SECONDS);
  assert.equal(implementation.name, "issue-54-implementer");
  assert.equal(review.name, "issue-54-reviewer");
  assert.equal(integration.name, "issue-54-integrator");
  assert.equal(integration.promptFile, "./.sandcastle/integration-prompt.md");
});

test("Codex provider uses the current automatic-review CLI flag", () => {
  const agent = createCodexAgent();
  const options = {
    prompt: "Return only OK.",
    dangerouslySkipPermissions: true,
  } as Parameters<typeof agent.buildPrintCommand>[0];
  const command = agent.buildPrintCommand(options).command;

  assert.match(command, /(?:^| )--approve-for-me(?: |$)/);
  assert.doesNotMatch(command, /(?:^| )-a(?: |$)/);
  assert.doesNotMatch(
    command,
    /(?:^| )--dangerously-bypass-approvals-and-sandbox(?: |$)/,
  );

  if (process.platform !== "win32") {
    return;
  }

  const shimDirectory = mkdtempSync(join(tmpdir(), "sandcastle-codex-argv-"));
  try {
    writeFileSync(
      join(shimDirectory, "capture.mjs"),
      "console.log(JSON.stringify(process.argv.slice(2)));\n",
      "utf8",
    );
    writeFileSync(
      join(shimDirectory, "codex.cmd"),
      '@echo off\r\nnode "%~dp0capture.mjs" %*\r\n',
      "utf8",
    );

    const invocation = spawnSync(
      process.env.ComSpec || "cmd.exe",
      ["/d", "/s", "/c", command],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${shimDirectory}${delimiter}${process.env.PATH ?? ""}`,
        },
      },
    );
    assert.equal(invocation.status, 0, invocation.stderr);
    assert.deepEqual(JSON.parse(invocation.stdout.trim()), [
      "exec",
      "--json",
      "--approve-for-me",
      "-m",
      "gpt-5.4",
      "-c",
      "model_reasoning_effort=high",
    ]);
  } finally {
    rmSync(shimDirectory, { force: true, recursive: true });
  }
});
