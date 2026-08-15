import assert from "node:assert/strict";
import test from "node:test";
import {
  analyzeChecks,
  parseMaxIterations,
  selectNextIssue,
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
