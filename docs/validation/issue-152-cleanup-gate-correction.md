# #152 cleanup-failure review correction

Starting revision and Code Review fixed point:
`adae67b22afd3b8de65445b1ae49958bf27e187a`.
Implementation revision: `c83d87d32c7a27fb54733fbb5271b73e2caf1156`.
Specification: [#152](https://github.com/jmanuelng/WIN_PCinfo/issues/152), with
the applicable [#134](https://github.com/jmanuelng/WIN_PCinfo/issues/134) and
[#37](https://github.com/jmanuelng/WIN_PCinfo/issues/37) cleanup contracts.

This bounded correction addresses the original Spec review's P1: "On failure,
stop new scheduling, report the truthful terminal/blocked state." Failed viewing
recovery recorded exit 60 but left assessment and other work controls available;
later preparation could enable approval again. Existing-package viewing and
export could reach the same unsafe condition before assessment approval.

The shared sticky gate now cancels the waiting assessment, rejects its decision,
disables work controls and rejects routed work events. Preparation, terminal and
close updates retain the visible CleanupIncomplete state. Recovery and close
remain available. Successful deliberate recovery still requires a fresh
invocation before assessment. Existing protected evidence is preserved.

## Focused validation

Automated correction checkpoint: **Pass**. Fresh affected Standards review:
**Pending**. Fresh affected Spec review: **Pending**. Root dispatches both fresh
axes after this implementation turn; neither is waived or represented as passed.
The original Standards result remains zero hard violations and one nonblocking
Label naming judgment; this correction does not repeat that unchanged review.

RED: the generated WPF recovery action reported CleanupIncomplete while leaving
SelectRecipient enabled. The retained regression failed on that observable
control state before the product change.

Installed PowerShell 7.6.5 X64 executed the following checks serially:

| Command after `pwsh -NoLogo -NoProfile` | Observed result |
| --- | --- |
| `-File tests/StatusDeskCleanupGate.Tests.ps1` | Pass: recovery before preparation, recovery after approval becomes available, failed report closure, export ownership uncertainty |
| `-STA -File tests/StatusDeskCleanupGate.Tests.ps1 -StaChild -Scenario RecoveryEarly` | Pass after adding the deliberate successful-recovery assertion |
| `-File tests/StatusDeskWpf.Tests.ps1` | Pass: ordinary controlled comprehensive GUI assessment, protected report and cleanup |
| `-File tests/StatusDeskRecipientSelection.Tests.ps1` | Pass: existing recipient confirmation and selection |
| `-File tests/StatusDeskViewing.Tests.ps1` | Pass: explicit report closure and verified plaintext removal |

The regression substitutes native dialog choices, uses actual locked synthetic
viewing files, and simulates an OS file-identity race for export. Generated GUI
handlers, preparation, package admission, encryption, viewing, recovery and
export remain real. Every collector entry is blocked in this negative test so a
regression cannot run live collection. Each GUI case has a 25-second watchdog
and observes the blocked state across 20 subsequent 100-millisecond ticks.
Assertions verify no collection or new destination writes, exit 60, protected
package retention, routed approval refusal, and recovery/close availability.
The early-recovery case releases its file lock and proves the preserved recovery
action removes registered plaintext without reopening assessment approval.

The first viewing test driver attempted to read the browser Source before it was
available; its bounded failure was corrected to lock the sole generated `.view`
file in its owned synthetic root. The final viewing regression passed. All
test-owned locks, synthetic files, packages and recovery records were removed.
No real keys, profiles, trust, signing artifacts or live assessment changed.

Affected source, regression and generated candidate parsed without errors;
`git diff --check` passed. The full repository suite and unchanged crypto matrix
were not repeated under the user's focused-ticket cadence. Integrated regression
remains **Pending #158** and real delivered-app acceptance remains **Pending #161**.

## Changed unsigned candidate

Generated script SHA-256 (3,254,905 bytes):
`d3a08bc6b4cdd2a67ce1dd4232450fe42c9f463c6aae20ef5934c3d539880f98`.

Generated portable ZIP SHA-256 (4,788,362 bytes):
`a164562816b6f6318f792f496df9cbacd01d3f0c740df5896a656016de7620ef`.

The focused tests rebuilt these outputs from the corrected source. Generated
artifacts remain ignored. These changed bytes supersede the earlier #152
candidate for affected checks; historical signing and acceptance evidence cannot
authorize them. No new determinism, signing or live-acceptance claim is made.

## Review and next-owner handoff

The fixed point resolves and the committed diff is nonempty. Review only:

`git diff adae67b22afd3b8de65445b1ae49958bf27e187a...HEAD`

`git log adae67b22afd3b8de65445b1ae49958bf27e187a..HEAD --oneline`

Standards sources: original checkout `AGENTS.md`, `CONTEXT.md`,
`docs/agents/issue-tracker.md`, `triage-labels.md`, `domain.md`; integration
`CONTRIBUTING.md` and `.sandcastle/CODING_STANDARDS.md`. No ADR directory exists.
Apply the Code Review skill's full smell baseline separately from the assigned
#152 specification and the P1 above. Root owns review dispatch, separate axis
aggregation, the shared requirement register and GitHub delivery. #161 should
verify this failure gate and deliberate recovery on the final admitted candidate
alongside the existing #152 live handoff. No acceptance requirement is waived.
