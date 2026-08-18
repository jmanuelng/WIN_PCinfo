# Sandcastle workflow

This repository runs Sandcastle directly on its Windows host because its
PowerShell collectors and tests require Windows. There is no Docker or other
container boundary. Worktree agents are Grok 4.6 at extra-high reasoning
(`--reasoning-effort xhigh`) with `--always-approve`. That still has broad
host access. Run this workflow only in the dedicated secure VM and from a
clean checkout.

## One-time CLI authentication

Run these commands in the same IDE terminal that will launch Sandcastle:

```powershell
gh auth login -h github.com --web
gh auth status
grok login
grok models
```

Git authentication in an IDE does not replace either CLI login.

`grok-agent.mts` invokes headless Grok with `--output-format streaming-json`,
`--no-leader`, and a temp `--prompt-file`. Plain completion-marker lines are
treated as agent text so review can start after a successful implementer
commit. It does not use Codex.

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
npm run sandcastle:preflight -- --issue 66
npm run sandcastle:canary -- --issue 66
```

Preflight is read-only. The canary processes exactly one issue, sequentially.
`--issue` pins that ticket so an assigned or later frontier item cannot steal
the canary slot. Omit `--issue` to take the lowest eligible unassigned ticket.

After inspecting a successful canary, a run may process up to ten issues with
two independent tickets active at once:

```powershell
npm run sandcastle -- --max-iterations 10
```

`npm run sandcastle` already sets `--max-parallel 2`. The named
`sandcastle:canary` script forces `--max-iterations 1 --max-parallel 1`.

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
available for inspection as reported by the failing lane. Each lane failure
reconciles and prints its exact local branch, worktree disposition, remote
branch, pull-request/merge state, issue state, and local-versus-remote `main`
sync state.

## Fault tolerance (same gates)

These retries do not change eligibility, phase order, or `--max-parallel`.

- Preflight prints remaining Grok access-token TTL (never token values). There
  is no `grok refresh` command. Sandcastle runs silent `grok models` at
  preflight, before every Grok spawn, and again before each 401 retry so a
  long AFK can pass the ~6h access JWT using the stored refresh token.
- Headless Grok retries transient `401` / `no auth context` failures a few
  times. If those retries are exhausted, no new batches start; worktrees are
  preserved and the console tells you to run `grok login`.
- A phase moves forward only on Grok **exit 0** plus
  `<promise>COMPLETE</promise>` (implementer also needs a commit). COMPLETE
  then exit 1 is a failure, including on resume. The adapter logs that defect
  instead of ignoring the exit code.
- Agents still run tests from their prompts. The orchestrator still runs
  `pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1` after review as the
  independent merge bar. Console heartbeats every 60s show issue, phase, last
  tool or log line, and idle time.
- `gh` retries HTTP 502/503. Login falls back from `gh api user` to
  `gh auth status`. GraphQL discovery stays retry-only (no REST fallback).
- Sandbox setup that produces no worktree within five minutes releases the
  claim and continues the batch. Deep `artifacts/` and `.test-output` trees are
  removed with Windows long-path-safe deletion before `git worktree remove`.
- A self-claim with **no** local worktree is released before the next batch
  (rollback before work). A self-claim **with** a preserved worktree is
  resumed on that same branch: skip a phase only when its log contains
  `<promise>COMPLETE</promise>` **and** an exit-0 success marker, then still
  run the independent full suite.
- Host start ignores untracked `.sandcastle/notes/` and `.sandcastle/logs/`.
- Parent specifications stay ineligible while they have open children
  (`subIssuesSummary.completed === total`). Completed parents are eligible,
  matching Matt Pocock's original PRD rule. There is no extra `[Spec]` title
  filter.
