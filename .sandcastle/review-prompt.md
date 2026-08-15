# Task

Review the implementation of issue `#{{ISSUE_NUMBER}}` on branch `{{BRANCH}}`
against both the issue specification and repository standards. Correct every
material finding you can safely resolve.

# Context

## Branch diff

!`git diff {{BASE_BRANCH}}...{{BRANCH}}`

## Branch commits

!`git log {{BASE_BRANCH}}..{{BRANCH}} --oneline`

## Issue specification

!`gh issue view {{ISSUE_NUMBER}} --comments --json number,title,body,labels,comments,assignees,blockedBy,parent,state,url`

# Review process

1. Read `AGENTS.md`, `CONTEXT.md`, relevant ADRs, and
   @.sandcastle/CODING_STANDARDS.md.
2. Verify every requested behavior, constraint, edge case, and testable
   acceptance condition from the issue.
3. Check correctness, failure handling, bounded behavior, evidence honesty,
   security, privacy, and deterministic output.
4. Confirm new or changed behavior has meaningful regression coverage.
5. Improve clarity and maintainability where doing so reduces material risk;
   avoid unrelated refactors.
6. If corrections are needed, make them on this branch, run focused tests and
   `pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1`, then commit them with
   a message beginning `RALPH-REVIEW:`.
7. If the implementation is correct and clean, leave it unchanged.

Do not push, create or merge a pull request, close the issue, or alter its
labels or assignees. The orchestrator performs delivery only after this review
and its independent full test gate succeed.

Once complete, output:

<promise>COMPLETE</promise>
