import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import {
  GROK_MODEL,
  GROK_REASONING_EFFORT,
  buildGrokPrintCommand,
  createGrokAgent,
  parseGrokStreamLine,
} from "./grok-agent.mts";
import {
  createLaneRecovery,
  laneFailure,
  reconcileLaneRecovery,
} from "./recovery.mts";
import {
  AGENT_PHASE_IDLE_TIMEOUT_SECONDS,
  DEFAULT_MAX_PARALLEL_ISSUES,
  loginFromGitHubAuthStatus,
  analyzeChecks,
  buildImplementationPhaseOptions,
  buildIntegrationPhaseOptions,
  buildReviewPhaseOptions,
  createSerializedExecutor,
  isSafelyClaimedIssue,
  parseIssueNumber,
  parseMaxIterations,
  parseMaxParallel,
  requireEligibleIssue,
  resultHasCompletionSignal,
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

test("claim identity can be read from gh auth status when /user is unavailable", () => {
  assert.equal(
    loginFromGitHubAuthStatus(
      "github.com\n  ✓ Logged in to github.com account jmanuelng (keyring)\n  - Active account: true",
    ),
    "jmanuelng",
  );
  assert.equal(loginFromGitHubAuthStatus("error: HTTP 503"), undefined);
});

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

test("parseIssueNumber pins a single canary ticket", () => {
  assert.equal(parseIssueNumber([]), undefined);
  assert.equal(parseIssueNumber(["--issue", "66"]), 66);
  assert.throws(() => parseIssueNumber(["--issue"]), /positive issue number/);
  assert.throws(() => parseIssueNumber(["--issue", "0"]), /positive issue number/);
});

test("requireEligibleIssue fails closed when the pin is not claimable", () => {
  const eligible = issue(66);
  const assigned = issue(66, { assignees: [{ login: "agent" }] });
  const commands: WorkflowCommandAdapter = {
    run: () => commandResult(),
    json<T>() {
      return eligible as T;
    },
  };
  assert.equal(requireEligibleIssue(66, commands).number, 66);

  const blocked: WorkflowCommandAdapter = {
    ...commands,
    json<T>() {
      return assigned as T;
    },
  };
  assert.throws(
    () => requireEligibleIssue(66, blocked),
    /not an unassigned, unblocked ready-for-agent ticket/,
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

test("the independent full-suite harness switches the host to UTF-8 first", () => {
  const harness = readFileSync(join(process.cwd(), "tests", "Run-Tests.ps1"), "utf8");
  assert.match(harness, /chcp 65001/);
  assert.match(harness, /UTF8Encoding/);
});

test("Grok provider uses extra-high reasoning and always-approve", () => {
  const agent = createGrokAgent();
  const options = {
    prompt: "Return only OK.",
    dangerouslySkipPermissions: true,
  } as Parameters<typeof agent.buildPrintCommand>[0];
  const command = agent.buildPrintCommand(options).command;

  assert.match(command, /(?:^| )--always-approve(?: |$)/);
  assert.match(command, /(?:^| )--reasoning-effort xhigh(?: |$)/);
  assert.match(command, new RegExp(`(?:^| )-m ${GROK_MODEL}(?: |$)`));
  assert.match(command, /(?:^| )--output-format streaming-json(?: |$)/);
  assert.match(command, /(?:^| )--prompt-file(?: |$)/);
  assert.match(command, /(?:^| )--no-leader(?: |$)/);
  assert.doesNotMatch(command, /'/);
  assert.equal(GROK_REASONING_EFFORT, "xhigh");

  assert.deepEqual(parseGrokStreamLine("<promise>COMPLETE</promise>"), [
    { type: "text", text: "<promise>COMPLETE</promise>" },
    { type: "result", result: "<promise>COMPLETE</promise>" },
  ]);
  assert.deepEqual(parseGrokStreamLine('{"type":"text","data":"<promise>COMPLETE</promise>"}'), [
    { type: "text", text: "<promise>COMPLETE</promise>" },
    { type: "result", result: "<promise>COMPLETE</promise>" },
  ]);
  assert.deepEqual(
    parseGrokStreamLine('{"text":"done\\n<promise>COMPLETE</promise>"}'),
    [
      { type: "text", text: "done\n<promise>COMPLETE</promise>" },
      { type: "result", result: "done\n<promise>COMPLETE</promise>" },
    ],
  );
  assert.ok(
    resultHasCompletionSignal({
      stdout: "summary\n<promise>COMPLETE</promise>\n",
    }),
  );
  assert.equal(resultHasCompletionSignal({ stdout: "still working" }), false);

  // Sandcastle matches completion against the LAST parsed `result` event, not
  // the log. A trailing Grok status/result after COMPLETE used to overwrite
  // that buffer and make a finished implementer look unfinished.
  let lastResultText = "";
  for (const line of [
    '{"type":"assistant","message":{"content":[{"type":"text","text":"committed\\n<promise>COMPLETE</promise>"}]}}',
    "<promise>COMPLETE</promise>",
    '{"type":"result","result":"success"}',
    '{"type":"end","sessionId":"abc","usage":{"input_tokens":1,"output_tokens":2}}',
  ]) {
    for (const parsed of parseGrokStreamLine(line)) {
      if (parsed.type === "result") {
        lastResultText = parsed.result;
      }
    }
  }
  assert.match(lastResultText, /<promise>COMPLETE<\/promise>/);
  assert.ok(resultHasCompletionSignal({ stdout: lastResultText }));
  assert.ok(
    resultHasCompletionSignal({
      stdout: "success",
      phaseLog: "committed\n<promise>COMPLETE</promise>\nAgent stopped\n",
    }),
  );
  assert.equal(
    resultHasCompletionSignal({
      stdout: "success",
      phaseLog: "Agent still working",
    }),
    false,
  );
  assert.deepEqual(
    parseGrokStreamLine(
      '{"type":"tool_call","toolName":"read_file","rawInput":{"path":"README.md"}}',
    ),
    [{ type: "tool_call", name: "read_file", args: '{"path":"README.md"}' }],
  );
  assert.deepEqual(
    parseGrokStreamLine(
      '{"type":"end","sessionId":"abc","usage":{"input_tokens":1,"output_tokens":2}}',
    ),
    [
      { type: "session_id", sessionId: "abc" },
      {
        type: "usage",
        usage: {
          inputTokens: 1,
          cacheCreationInputTokens: 0,
          cacheReadInputTokens: 0,
          outputTokens: 2,
        },
      },
    ],
  );

  if (process.platform !== "win32") {
    return;
  }

  const built = buildGrokPrintCommand("Return only OK.");
  const shimDirectory = mkdtempSync(join(tmpdir(), "sandcastle-grok-argv-"));
  try {
    writeFileSync(
      join(shimDirectory, "capture.mjs"),
      "console.log(JSON.stringify(process.argv.slice(2)));\n",
      "utf8",
    );
    writeFileSync(
      join(shimDirectory, "grok.cmd"),
      '@echo off\r\nnode "%~dp0capture.mjs" %*\r\n',
      "utf8",
    );

    const invocation = spawnSync(
      process.env.ComSpec || "cmd.exe",
      ["/d", "/s", "/c", built.command],
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
      "--prompt-file",
      built.promptPath,
      "--output-format",
      "streaming-json",
      "--always-approve",
      "--no-leader",
      "--no-alt-screen",
      "--no-plan",
      "--verbatim",
      "--reasoning-effort",
      "xhigh",
      "-m",
      "grok-4.6",
    ]);
  } finally {
    rmSync(shimDirectory, { force: true, recursive: true });
  }
});
