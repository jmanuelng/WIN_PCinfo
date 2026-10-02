# Retired development runner

The Grok-based Sandcastle runner was retired at the maintainer's request on
October 1, 2026. It was development orchestration tooling; the WIN-PCInfo
application never required Grok or Sandcastle.

Its executable sources, phase prompts, npm commands and npm dependencies have
been removed. Development continuation uses the current Codex chat and the
repository's GitHub issue specifications.

The local logs, preserved worktrees and ignored configuration remain available
for recovery. The ignore rules are retained so those local artifacts do not enter
source control. Historical runner code is recoverable from Git history.

Retirement does not qualify unfinished application changes or start an AFK run.
