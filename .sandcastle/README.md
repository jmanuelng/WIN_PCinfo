# Sandcastle workflow

This repository runs Sandcastle directly on its Windows host because its
PowerShell collectors and tests require Windows. There is no Docker or other
container boundary. Codex uses automatic approval review, but it still has
broad host access. Run this workflow only in the dedicated secure VM and from a
clean checkout.

## One-time CLI authentication

Run these commands in the same IDE terminal that will launch Sandcastle:

```powershell
gh auth login -h github.com --web
gh auth status
codex login
codex login status
```

Git authentication in an IDE does not replace either CLI login.

The pinned Sandcastle `0.12.0` Codex provider predates the current Codex CLI
automatic-review flag. `codex-agent.mts` adapts its generated command to
`--approve-for-me` and fails closed if Sandcastle changes the expected command
shape. Do not replace the adapter with approval bypass.

## Eligibility

Sandcastle considers only open issues that:

- have the `ready-for-agent` label;
- have no assignee; and
- have no open blocker.

GitHub may retain closed historical dependencies in `blockedBy.nodes`; those
entries do not block selection. A dependency with a missing or unrecognized
state fails closed and remains blocking.

It assigns every selected issue to the authenticated GitHub user before
creating branches. Selection is deterministic: the lowest eligible issue
numbers fill the available frontier slots first. Each claim rechecks state,
label, blockers, child completion, and sole ownership before work begins. If a
later claim fails, every earlier claim in that not-yet-started batch is released
and verified; an unverifiable rollback stops with an exact per-issue error.

## Safe first run

From an up-to-date, clean `main` checkout:

```powershell
npm install
npm run sandcastle:test
npm run sandcastle:preflight
npm run sandcastle:canary
```

Preflight is read-only. The canary processes at most one issue.

After inspecting a successful canary, a run may process up to ten issues with
at most two independent tickets active at once:

```powershell
npm run sandcastle -- --max-iterations 10
```

`npm run sandcastle` uses the same ten-issue default. The named
`sandcastle:canary` script explicitly limits execution to one issue.

Use `--max-parallel 1` to force sequential execution. The default and maximum
are both two because this no-sandbox Windows host must retain enough capacity
for two complete PowerShell suites.

Each batch fetches `origin/main`, claims up to two eligible issues, and gives
each issue a dedicated worktree and fresh implementation/review agent context.
Agent phases and full test gates may overlap. Delivery is serialized: before a
branch is pushed, it must contain the latest `origin/main`. If another lane
merged first, Sandcastle integrates that base, invokes a dedicated integration
agent for semantic merge conflicts, and reruns the complete PowerShell suite.
It then creates the pull request, waits for checks, squash-merges, and verifies
issue closure.

Any failure stops new deliveries and prevents another batch from starting. A
delivery already in progress is allowed to finish its atomic transaction.
Started issues remain assigned; claims rolled back before work are reported as
released. Branches, preserved dirty worktrees, and pull requests remain
available for inspection as reported by the failing lane.
