# Issue #165 synthetic qualification fixture time

Scope: [#165](https://github.com/jmanuelng/WIN_PCinfo/issues/165), the bounded
regression blocking #135 under #134/#37. Starting revision and independent
Code Review fixed point: `195659552e09479f33518ec3b0ae7a23bfa955ab`.

Status: focused regression passes; full repository gate and independent review
are pending. This record establishes synthetic test behavior only. It does not
establish live assessment, Preview qualification, Supported status or publication.

## Clock strategy and boundary

The generated public application retains its production UTC evaluation clock.
Only `tests/PreviewQualificationApplication.Tests.ps1` changes. Each run captures
one UTC instant and creates disposable requests from the explicitly synthetic
complete fixture. Before assigning dates, setup requires the request and evidence
pack synthetic flags and the `SyntheticProjection` evidence kind. It writes
invariant UTC observation times into the synthetic pack, gates and scenarios:

- Positive: one day before that captured instant, safely inside freshness limits.
- Expired negative: 31 days before that same instant, beyond the existing 30-day
  Client VM window with a full day of margin.

The checked-in August 1 fixture remains unchanged; it is still used with a fixed
evaluation clock by the qualification module tests and read by the policy/schema
test. These are the only other consumers. No real evidence is loaded or renewed.
The generated request keeps exact current content and ledger digest bindings and
the existing explicitly synthetic final-artifact identity. These synthetic
identities are not evidence of real signing or final-artifact execution.

No production code, future-date rule, validity window, invalidation behavior,
trust gate, publication gate or application clock input changes. No new live
clock/admission seam, permanent timestamp or skipped assertion is introduced.

## Red/green and focused evidence

Environment: Windows, explicit installed PowerShell Core 7.6.5 X64, existing
UTF-8 test-host setup, September 5, 2026. All data are synthetic/controlled.
Commands use `& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File`
followed by the repository-relative test path below.

| Check | Observed outcome | Duration |
| --- | --- | --- |
| Original `tests/PreviewQualificationApplication.Tests.ps1` | Red, exit 1: expected Approved, received Denied with stale August evidence | 9.10 s |
| Positive with generated recent synthetic dates | Green, exit 0; existing application assertions pass | Not separately timed |
| Added expired-negative assertion temporarily supplied recent observations | Red, exit 1: expected Denied, received Approved; assertion detects qualification acceptance | 11.64 s |
| Final `tests/PreviewQualificationApplication.Tests.ps1` with 31-day-old negative | Green, exit 0 | 16.82 s |
| Qualification module, qualification policy, ReleaseGates module, BuildDeterminism | All four pass, exit 0 | 56.69 s combined |
| PowerShell parser and `git diff --check` | Pass | Not separately timed |

The generated positive retains Approved/Qualify, exact candidate binding,
schema-valid packet/manifest, one completed terminal, no collection/publication
and verified absence of derived workspace files. The generated negative reports
Denied/Deny with `QUALIFY.EXPIRED`, all three Client VM manifest gates Expired,
content and final artifact unqualified, one Completed/`QUALIFY.DENIED` terminal,
no collection/publication and verified cleanup. The module regressions retain
missing, product-failed, invalidated, wrong-candidate and expired evidence cases;
ReleaseGates retains 90-day cloud expiry and dishonest freshness-class rejection.

## Integrated completion gate and review

Required command: `& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File ./tests/Run-Tests.ps1`.
The full 123-file gate will run on the committed integrated source. It requires
bounded sandbox permission for existing synthetic public-directory rejection
tests and their owned cleanup; this is not product or machine elevation.

- Full-suite result: pending; no complete passing suite is claimed.
- Standards axis: pending independent review against the fixed point above.
- Spec axis: pending independent review against #165 and that same fixed point.

## Exact candidates and remaining gates

Focused builds reproduce the starting artifact bytes exactly (SHA-256):

| Artifact | Digest |
| --- | --- |
| Generated `WIN-PCInfo.ps1` | `d834aee6eef1fb4daabcbea11d6e6be6001cac9d1a25fa7f53c22246b071b745` |
| Portable zip | `b8ed77f78e4039b70a6c2a95f4e020a87fbb6c95fd165fd06b16b85cb7b2d57c` |

Generated files and synthetic requests remain ignored. #135 is not merged or
accepted merely because focused tests pass. The orchestrator owns integrated
readiness, push/PR/merge and issue closure. #157/#158 release work, all #37/#134
requirements and live/personal GUI, signing, Azure and publication gates remain
separate. The September 6 validated-preview target remains at risk.
