import {
  assertAuthentication,
  assertHostReady,
  authenticatedGitHubLogin,
  listEligibleIssues,
  listLocalIssueLanes,
  parseIssueNumber,
  requireStartableIssue,
  selectNextIssue,
} from "./workflow.mts";

function run(): void {
  const requestedIssueNumber = parseIssueNumber(process.argv.slice(2));
  console.log("Checking GitHub and Grok CLI authentication...");
  assertAuthentication();

  console.log("Checking repository state and refreshing origin/main...");
  assertHostReady();

  console.log("Reading eligible issues without claiming or modifying them...");
  const issue =
    requestedIssueNumber === undefined
      ? selectNextIssue(listEligibleIssues())
      : requireStartableIssue(
          requestedIssueNumber,
          authenticatedGitHubLogin(),
          listLocalIssueLanes(),
        );
  if (!issue) {
    console.log("PASS: no unassigned, unblocked ready-for-agent issue is available.");
    return;
  }

  console.log(
    requestedIssueNumber === undefined
      ? `PASS: next canary candidate is #${issue.number}: ${issue.title}`
      : `PASS: pinned canary candidate is #${issue.number}: ${issue.title}`,
  );
  console.log("Preflight made no issue, branch, pull-request, or source changes.");
}

try {
  run();
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`FAIL: ${message}`);
  process.exitCode = 1;
}
