# Issue #165 synthetic qualification fixture time

Scope: [#165](https://github.com/jmanuelng/WIN_PCinfo/issues/165), the bounded
regression blocking #135 under #134/#37. Starting revision and independent
Code Review fixed point: `195659552e09479f33518ec3b0ae7a23bfa955ab`.

Status: qualification and release-gate generated regressions and the full
123-file repository gate pass. Independent review is pending.
This record establishes synthetic test behavior only. It does not
establish live assessment, Preview qualification, Supported status or publication.

## Clock strategy and boundary

The generated public application retains its production UTC evaluation clock.
The repairs change `tests/PreviewQualificationApplication.Tests.ps1` and the
same-cause consumer `tests/ReleaseGatesApplication.Tests.ps1`. Each test captures
one UTC instant and creates disposable inputs from its explicitly synthetic
complete fixture. Before assigning dates, qualification setup requires the request and evidence
pack synthetic flags and the `SyntheticProjection` evidence kind. It writes
invariant UTC observation times into the synthetic pack, gates and scenarios.
Release-gate setup likewise requires its pack's synthetic flag before dating it:

- Positive: one day before that captured instant, safely inside freshness limits.
- Expired negative: 31 days before that same instant, beyond the existing 30-day
  Client VM window with a full day of margin.

Both checked-in August 1 fixtures remain unchanged. Each still has only its
module test (fixed evaluation clock), policy/schema test and generated application
test as consumers. No real evidence is loaded or renewed.
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
| Related `tests/ReleaseGatesApplication.Tests.ps1` | Red, exit 1: expected qualified content, received false from static August pre-signing evidence | 7.35 s |
| Release-gate positive with recent synthetic dates | Green, exit 0 | 13.08 s |
| Added release-gate expired assertion temporarily supplied recent observations | Red, exit 1: expected unqualified, received qualified | 8.84 s |
| Release-gate negative after aging observations | Test assertion referenced nonexistent `promotion.eligible`; corrected to documented `previewPromotionReady` and `publicationAuthorized` | 9.38 s, exit 1 |
| Final `tests/ReleaseGatesApplication.Tests.ps1` | Positive and expired negative green, exit 0 | 14.42 s |

The generated positive retains Approved/Qualify, exact candidate binding,
schema-valid packet/manifest, one completed terminal, no collection/publication
and verified absence of derived workspace files. The generated negative reports
Denied/Deny with `QUALIFY.EXPIRED`, all three Client VM manifest gates Expired,
content and final artifact unqualified, one Completed/`QUALIFY.DENIED` terminal,
no collection/publication and verified cleanup. The module regressions retain
missing, product-failed, invalidated, wrong-candidate and expired evidence cases;
ReleaseGates retains 90-day cloud expiry and dishonest freshness-class rejection.
The additional generated release-gate case preserves exact candidate bindings,
reports all three Client VM gates Expired, and denies content qualification and
Preview promotion/publication while completing evaluation without collection.

## Integrated completion gate and review

Required command: `& 'C:/Program Files/PowerShell/7/pwsh.exe' -NoLogo -NoProfile -File ./tests/Run-Tests.ps1`.
The full 123-file gate ran on committed integrated source
`9b9a6c88c54840e7f969abf433946bf9b100163d` on September 5, 2026, using the explicit
PowerShell Core 7.6.5 X64 host above. It passed, exit 0, in **3,052.52 seconds**
(50 minutes 52.52 seconds). Bounded sandbox permission covered existing synthetic
public-directory rejection tests and their owned cleanup; no product or machine
elevation was introduced. There were no exclusions or retries.

- Full-suite result: **Pass, all 123 test files completed.** This includes both
  repaired generated application tests, existing qualification/release expiry
  negatives, runtime/portable launch tests, guided/automation contracts, synthetic
  Azure/signing/publication gates, report/contract/collector coverage, protected
  package/recipient/export checks and lifecycle/privilege/SYSTEM cleanup cases.
- Standards axis: pending independent review against the fixed point above.
- Spec axis: pending independent review against #165 and that same fixed point.

The full suite reproduces the exact application and portable-archive digests
below. It therefore resolves #135's known branch-local full-test blocker on the
same #135 generated bytes. The earlier failed runs remain historical evidence
in `docs/validation/issue-135-runtime-selection.md`; this record does not rewrite
them or supply a new review of unchanged runtime implementation. The orchestrator
combines this run with the existing #135 reviews to decide integrated readiness.

## Exact candidates and remaining gates

Focused builds reproduce the starting artifact bytes exactly (SHA-256):

| Artifact | Digest |
| --- | --- |
| Generated `WIN-PCInfo.ps1` | `d834aee6eef1fb4daabcbea11d6e6be6001cac9d1a25fa7f53c22246b071b745` |
| Portable zip | `b8ed77f78e4039b70a6c2a95f4e020a87fbb6c95fd165fd06b16b85cb7b2d57c` |

Generated files, local full-suite logs and synthetic requests remain ignored.
#135 is not merged or closed by this passing branch-local gate. The orchestrator owns integrated
readiness, push/PR/merge and issue closure. #157/#158 release work, all #37/#134
requirements and live/personal GUI, signing, Azure and publication gates remain
separate. The September 6 validated-preview target remains at risk.
