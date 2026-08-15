import {
  assertAuthentication,
  assertHostReady,
  listEligibleIssues,
  selectNextIssue,
} from "./workflow.mts";

function run(): void {
  console.log("Checking GitHub and Codex CLI authentication...");
  assertAuthentication();

  console.log("Checking repository state and refreshing origin/main...");
  assertHostReady();

  console.log("Reading eligible issues without claiming or modifying them...");
  const issue = selectNextIssue(listEligibleIssues());
  if (!issue) {
    console.log("PASS: no unassigned, unblocked ready-for-agent issue is available.");
    return;
  }

  console.log(`PASS: next canary candidate is #${issue.number}: ${issue.title}`);
  console.log("Preflight made no issue, branch, pull-request, or source changes.");
}

try {
  run();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`FAIL: ${message}`);
  process.exitCode = 1;
}
