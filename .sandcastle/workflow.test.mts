import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createCodexAgent } from "./codex-agent.mts";
import {
  AGENT_PHASE_IDLE_TIMEOUT_SECONDS,
  DEFAULT_MAX_PARALLEL_ISSUES,
  analyzeChecks,
  buildImplementationPhaseOptions,
  buildIntegrationPhaseOptions,
  buildReviewPhaseOptions,
  createSerializedExecutor,
  parseMaxIterations,
  parseMaxParallel,
  runCommandAsync,
  selectNextIssue,
  selectNextIssues,
  type GitHubIssue,
} from "./workflow.mts";

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

test("parseMaxIterations defaults to one and caps autonomous runs", () => {
  assert.equal(parseMaxIterations([]), 1);
  assert.equal(parseMaxIterations(["--max-iterations", "10"]), 10);
  assert.throws(
    () => parseMaxIterations(["--max-iterations", "11"]),
    /integer from 1 through 10/,
  );
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

test("serialized executor delivers one lane at a time and survives failures", async () => {
  const execute = createSerializedExecutor();
  const events: string[] = [];
  const first = execute(async () => {
    events.push("first:start");
    await new Promise((resolve) => setTimeout(resolve, 20));
    events.push("first:fail");
    throw new Error("expected failure");
  });
  const second = execute(async () => {
    events.push("second:start");
    events.push("second:done");
    return 2;
  });

  await assert.rejects(first, /expected failure/);
  assert.equal(await second, 2);
  assert.deepEqual(events, [
    "first:start",
    "first:fail",
    "second:start",
    "second:done",
  ]);
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
