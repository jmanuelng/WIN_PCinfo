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

## Eligibility

Sandcastle considers only open issues that:

- have the `ready-for-agent` label;
- have no assignee; and
- have no open blocker.

It assigns the selected issue to the authenticated GitHub user before creating
a branch. Selection is deterministic: the lowest eligible issue number wins.

## Safe first run

From an up-to-date, clean `main` checkout:

```powershell
npm install
npm run sandcastle:test
npm run sandcastle:preflight
npm run sandcastle:canary
```

Preflight is read-only. The canary processes at most one issue.

After inspecting a successful canary, a sequential run may process up to ten
issues:

```powershell
npm run sandcastle -- --max-iterations 10
```

Each iteration fetches `origin/main`, claims one eligible issue, implements and
reviews it in a dedicated worktree, runs the complete PowerShell test suite,
pushes the branch, creates a pull request, waits for checks, squash-merges it,
and verifies issue closure before starting the next iteration.

Any failure stops the loop. The issue remains assigned, and any branch,
worktree, or pull request already created remains available for inspection.
