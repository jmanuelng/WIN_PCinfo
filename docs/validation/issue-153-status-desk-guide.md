# #153 Status desk controls and beginner guidance

Implementation checkpoint, 2026-09-06. This is synthetic/controlled validation,
not live application acceptance, personal signing, Preview qualification or a
Supported claim. Independent Standards and Spec reviews are **Pending**.

## Source and scope

- Fixed point: `45af3797719c397015e63b01ca2548f791daf0fe`.
- First implementation: `a5ea372a0f8863c9804dae96e3c96f337fdc0687`.
- Final implementation: `44443034a386446f6dd6adcd0e1bf178e4aceeaf`.
- Specification: [#153](https://github.com/jmanuelng/WIN_PCinfo/issues/153),
  inheriting #134/#37; implementation allocation and final regression remain #158.

The generated Status desk exposes network/output changes before approval, one
fixed Comprehensive scope, existing zero/one-recipient selection and separate
setup, and fresh preparation/retry after verified cleanup. Changes replace the
request and require new approval. Selected network authority stays consistent
with the chosen network behavior. The existing #152 sticky cleanup-failure gate
also disables both new actions, including routed clicks and later timer updates.
Deliberate recovery and close remain available; successful recovery does not
unlock the failed invocation.

Passive GUI Help/About describe the complete runway without navigation, telemetry,
upload or feedback prompts. Outcome text explains safe next actions; bounded
activity has elapsed timestamps and readable phases/states, with heartbeat text
explicitly distinguishing controller responsiveness from source progress. The
main window, activity, choices, help and recipient dialogs wrap/scroll; initial,
running and completion focus targets are explicit. Existing report rendering,
protection and report keyboard styles are reused, not rewritten.

The Guided Runway now describes the real `Start-WIN-PCInfo.cmd` portable entry,
private candidate verification, personal versus public trust, GUI preparation,
cancel/close, retry/recovery, report viewing, warned private export, recipient
setup and safe key retention/removal. Runtime instructions no longer describe
the obsolete post-approval execution stub. MIT/DCO/contribution, conditional
field evidence and best-effort/no-SLA boundaries remain explicit.

## Focused checks

All commands used installed PowerShell 7.6.5 X64, `pwsh -NoLogo -NoProfile -File
tests/<name>.Tests.ps1`. Tests ran serially; STA wrappers use that same installed
host. No dependencies were acquired. Durations are wall-clock seconds.

| Check | Exact source | Result | Seconds |
| --- | --- | --- | ---: |
| StatusDeskChoices | a5ea372 | Pass | 15.19 |
| StatusDeskEntry | a5ea372 | Pass | 7.95 |
| StatusDeskWpf | a5ea372 | Pass | 24.79 |
| StatusDeskCleanupGate | a5ea372 | Pass, all four scenarios | 44.45 |
| StatusDeskRecipientSelection | a5ea372 | Pass | 6.89 |
| ProductHelpApplication | a5ea372 | Pass | 28.04 |
| ProductHelp | a5ea372 | Pass | 0.59 |
| GuidedRunwayDocumentation | a5ea372 | Pass | 0.63 |
| StatusDeskChoices | 4444303 | Pass | 15.38 |
| GuidedRunwayDocumentation | 4444303 | Pass | 0.61 |
| LaunchContract | 4444303 | Pass | 12.01 |

The final follow-up corrects the launcher name, resolves the initial relative
destination, and synchronizes the chosen network-authority boolean. Its affected
choices/docs/console checks were rerun. Other focused evidence above is attributed
to a5ea372, not represented as a rerun on 4444303. Report, cleanup-gate and recipient
handlers did not change in that follow-up. Parsing all changed PowerShell files
and the final generated application produced zero errors; `git diff --check`
passed. The full suite was deliberately not run under the per-ticket cadence;
#158/final owns integrated regression.

RED evidence: generated control discovery first failed because ChangeChoices
did not exist. The new documentation assertion then failed for missing GUI
instructions, after correcting its obsolete workflow list to include the
already-implemented OpenReport. The heartbeat test failed before its English
presentation function existed. Each retained check subsequently passed.

An initial in-process full-entry modal driver stalled during test development.
Its same-timer modal handling, relative-path input and callback context were
isolated; the choices/retry test now exercises generated production definitions
through the established ViewReady seam. The unchanged full ApplicationMain entry
is separately exercised for preparation/decline. The first two stalled synthetic
test process pairs were identified by exact command line and stopped; no live
collection was authorized or performed. Later attempts had a bounded driver
timeout. These failed attempts are not passing acceptance evidence.

## Candidate and disposition

Generated from the clean final implementation source 4444303:

- `WIN-PCInfo.ps1`: 3,304,709 bytes; SHA-256
  `100683ff5158b781b3b090f0f083a1b3b99511ee13179b6dc5ecdf2a16bf09ac`.
- Portable ZIP: 4,851,312 bytes; SHA-256
  `78f25bd7a35530a70bd2ff19f9aceb35af7cdbe3fdff29cd4dac91b4f03aa3ce`.
- Build provenance content-tree SHA-256:
  `4e89e209c7d6cd8681f1fb4f1493930a50cdf5c0e8c96be91b9a51ae95a6540a`.

These are unsigned precursor identities, not signed distributable identities.
Generated candidate/portable files remain ignored local build outputs. Tests
remove their conclusively owned synthetic package/viewing resources after
resolved-path checks. Existing unrelated artifacts were preserved. No real
certificate creation, trust mutation, signing, key export/removal, UAC, live
assessment, cloud operation or private #160 artifact change occurred.

## Required review and live handoff

Implement, TDD and Code Review were invoked. Code Review fixed-point resolution,
nonempty three-dot diff and DCO commit list were verified. Root must dispatch the
two fresh independent axes sequentially after this worker ends because of the
known retained-slot constraint; no prior-ticket review is reused.

- Standards: **Pending**. Sources: original checkout AGENTS.md, CONTEXT.md and
  docs/agents instructions; integration .sandcastle/CODING_STANDARDS.md and
  CONTRIBUTING.md; Code Review smell baseline. No applicable ADR directory exists.
- Spec: **Pending**. Review the full fixed-point diff against #153 and inherited
  relevant #134/#37 requirements, with #158 allocation.
- #161: **Pending live** exact-candidate beginner Choose/Verify/Prepare/Run/
  Interpret/Troubleshoot/Share session; every exposed control, keyboard order and
  focus, common displays/scales, embedded report and Edge, cancellation/close,
  recovery, private export and recipient reopening. Fixtures do not prove success.
- #158: **Pending** complete application regression and private acceptance
  preparation. #160 retains its own first real assessment and trust-session gates.
- Root owns the requirement ledger, both reviews, corrections/reviews as needed,
  and GitHub delivery. Do not close #153 before both required axes qualify.

## Final review disposition

Original fresh Standards0blocking/1nonblocking duplication and Spec1P2 required a bounded recovery correction. See issue-153-recovery-correction.md for the observed failures, new source650be94, seven affected passing checks, exact candidate96e303bb... and both fresh affected review results: Standards0hard/0newsmells; Spec0,originalP2resolved. #153 automated implementation qualifies for delivery; #158 and #160/#161 gates above remain pending. Earlier Pending entries describe the historical worker checkpoint, not the final review state.
