# Task

Resolve the in-progress merge of `{{BASE_BRANCH}}` into issue `#{{ISSUE_NUMBER}}`
on branch `{{BRANCH}}`. Preserve both the issue implementation and every change
already merged to the base branch.

# Context

## Merge state

!`git status --short`

## Unmerged paths

!`git diff --name-only --diff-filter=U`

## Issue specification

!`gh issue view {{ISSUE_NUMBER}} --comments --json number,title,body,labels,comments,assignees,blockedBy,parent,state,url`

# Integration process

1. Read `AGENTS.md`, `CONTEXT.md`, relevant ADRs, and
   @.sandcastle/CODING_STANDARDS.md.
2. Resolve every conflict semantically. Do not choose one side wholesale when
   the contracts, schemas, generated mirrors, tests, or documentation require
   both sets of changes.
3. Run focused validation for every conflicted surface.
4. Complete the merge with a commit beginning `RALPH-INTEGRATION:`.
5. Leave the worktree clean. The orchestrator runs the complete PowerShell
   suite after this phase.

Do not push, create or merge a pull request, close the issue, or alter labels
or assignees.

Once complete, output:

<promise>COMPLETE</promise>
