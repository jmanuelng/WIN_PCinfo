# #153 terminal request correction

Controlled implementation checkpoint, 2026-09-06. This corrects the original
Spec review P2 about recovering from an unavailable recipient. Earlier #153
evidence remains historical; this checkpoint does not claim live acceptance.

## Source and behavior

- Correction fixed point: `35c5a3a2a2be06024910d1792061baa224c4297c`.
- Source DCO commit: `650be94e2f5205cc4f5feacc1080c8633ec7650f`.
- Spec: [#153](https://github.com/jmanuelng/WIN_PCinfo/issues/153), inheriting
  #134/#37; integrated acceptance belongs to #158.

The terminal screen retains an unavailable preparation's prerequisite details.
After verified cleanup, Change network / output and Select recipient remain
available to correct the request before starting its fresh preparation. Recipient
setup retains its existing runtime/trust/fixture eligibility. Retry explicitly
repeats the current choices. Help and the Guided Runway describe these actions.

Each changed request starts a fresh invocation and requires a fresh decision;
the original frozen request is unchanged. Recipient changes now share the same
request-copy transition as choices/retry, including clearing stale-recovery
authorization. Completed decisions no longer prevent correcting the next request.
Disabled approval cannot be invoked through a routed click. Unverified cleanup
and #152's sticky viewing/setup/export cleanup failure still block new work;
successful later cleanup recovery does not reopen the failed invocation.

## RED and focused GREEN

The new generated WPF regression first failed because the terminal removed
`recipient-profile-resolved` from the visible unresolved prerequisites (9.00s).
After retaining those details, it failed because Select recipient was disabled
(8.94s). Both failures were observed through the production generated controls.
An intermediate test assertion confused fixture-resolved destination with the
requested destination; it was corrected to inspect the public frozen plan's
requested destination, keeping the declared fixture resolution honest.

The retained regression waits beyond terminal rendering, changes network/output
while the unavailable recipient remains unresolved, deliberately selects no
recipient, and verifies fresh approval readiness. It then declines and corrects
again, checking the completed-decision path. Four invocations produce no
collection and leave the original request unchanged. Existing controls and
preparation execute; collection boundaries have defensive fail-before-live
guards, and no assessment is approved.

All checks below ran serially on source `650be94`, using installed PowerShell
7.6.5 X64: `pwsh -NoLogo -NoProfile -File tests/<name>.Tests.ps1`.

| Check | Result | Seconds |
| --- | --- | ---: |
| StatusDeskRecoveryCorrection | Pass | 10.71 |
| StatusDeskChoices | Pass, including generated choices/retry entry | 15.82 |
| StatusDeskRecipientSelection | Pass | 6.79 |
| StatusDeskCleanupGate | Pass, all four scenarios | 43.62 |
| StatusDeskEntry | Pass | 7.95 |
| GuidedRunwayDocumentation | Pass | 0.64 |
| BuildDeterminism | Pass, identical relocated and LF/CRLF builds | 52.64 |

The changed PowerShell source, retained regression and generated application
parse with zero errors. `git diff --check` passes. Full-suite execution is
reserved for #158/final under the authorized focused per-ticket cadence.

## Exact unsigned candidate and disposition

Generated from source `650be94`:

- Application: 3,305,302 bytes; SHA-256
  `96e303bb6271506a24d1b26ead75cd3e803e2db0052ebd7f0c8cbb7f7b85f584`.
- Portable ZIP: 4,852,191 bytes; SHA-256
  `1436d1dfc3e55a270a79cd46611150e8c617a654a97fb1f52a9bf82f20a3fd9c`.
- Provenance content-tree SHA-256:
  `2baea1c8cfb8c781dcdc790655e37ccca6cb6d4625f3239f22c6041f143ec7e1`.

These ignored local outputs are unsigned precursors, not personally signed
artifacts or distributable release identities. Build mirrors remain ignored
test outputs. Existing focused cleanup tests remove their verified owned
synthetic resources; no unrelated artifact was removed. There was no live
collection, UAC, real certificate/key/trust/signing operation, cloud operation,
dependency acquisition, GitHub mutation or private #160 artifact change.

## Review and remaining gates

Implement, TDD and Code Review were invoked. The fixed point resolves, the
three-dot diff is nonempty, and the source commit includes DCO sign-off.
Review command: `git diff 35c5a3a2a2be06024910d1792061baa224c4297c...HEAD`.
The correction is the review scope; earlier unchanged #153 work is not rerun.

- Standards: **Pending fresh affected review**. Sources are original-checkout
  AGENTS.md, CONTEXT.md and docs/agents instructions; integration CONTRIBUTING.md
  and .sandcastle/CODING_STANDARDS.md; Code Review smell baseline.
- Spec: **Pending fresh affected review**, against #153's recovery and exposed
  controls requirements with the inherited safety boundary.
- Root dispatches both independent axes sequentially under the known retained
  slot constraint. No nested reviewer was spawned or old review reused.
- #158/final: **Pending** integrated regression and exact private candidate
  acceptance preparation. #161: **Pending live** beginner recovery, keyboard,
  common display/scaling and complete workflow acceptance on the exact candidate.
  #160 retains its own trust and first real assessment gates.

Do not close #153 from this checkpoint until both fresh review axes qualify.
Root owns the requirement ledger and transactional GitHub delivery.

## Independent review disposition

Original full slice: fixed point45af3797719c397015e63b01ca2548f791daf0fe to35c5a3a2a2be06024910d1792061baa224c4297c,8files+523/-43. Fresh Standards:0blocking breaches,1nonblocking request transition duplication. Fresh Spec:1P2; unavailable-recipient failure hid prerequisite details and prevented reliable correction before retry. That checkpoint did not qualify for closure.

Correction: fixed point35c5a3a2a2be06024910d1792061baa224c4297c toda770248faf4f1a387db5186ceb451ee68144ae3,4files+236/-17. Fresh independent Standards:0hard findings,0new nonblocking judgments; shared request transition also addresses the original duplication. Fresh independent Spec:0actionable findings,originalP2resolved. Unresolved prerequisites remain visible, post-cleanup correction produces fresh requests/approval, and sticky cleanup failure still blocks new work. Both axes inspected recorded evidence read-only without rerunning tests or duplicating the unchanged full diff.

The implementation slice now qualifies for orchestrator delivery. #158 integrated regression and #160/#161 real assessment/keyboard/display/workflow acceptance remain pending. This review record changes documentation only; it establishes no additional candidate execution or live evidence.
