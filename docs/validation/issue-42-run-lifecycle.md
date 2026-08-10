# Issue #42 Assessment Run lifecycle validation

This evidence is public-safe and entirely synthetic. It contains no Assessment Record from a real device, package, recovery journal, path, account, environment value, raw process output, credential, network fact, or Azure identifier.

## Observable seams

The primary exported seam is `Invoke-AssessmentRun`. It accepts only the orchestrator's approved collector, package-finalizer, and cleanup adapters, and returns structured progress, an applicable validated synthetic Assessment Record, one terminal record, and the stable exit code. Completion tests inject a synthetic test finalizer because issue #46 has not delivered the real Protected Evidence Package finalizer.

The generated application integrates the same module after request validation and accepted Preparation. Its hidden lifecycle fixture accepts exactly `Timeout`, `Cancellation`, or `PackageUnavailable`; each calls the release-owned Process Supervisor. The generated artifact cannot expose `Completed` or `CompletedWithGaps` in this slice.

## State and failure matrix

| Fixture | Outcome / exit | Evidence checked |
| --- | --- | --- |
| accepted completion | `Completed` / 0 | complete coverage, Contract Validator acceptance, injected verified package, verified cleanup |
| isolated collector failure | `CompletedWithGaps` / 10 | partial coverage and diagnostic remain visible; partial record validates and is protected |
| cancellation | `Cancelled` / 30 | one acknowledgement, no new scheduling, no recoverable normalized evidence in the fixture, owned cleanup verified |
| timeout | `TimedOut` / 40 | timeout coverage, finite policy at run/phase/operation/process levels, one attempt |
| worker loss | `IntegrityFailed` / 50 | failed coverage, sanitized reason, no private exception text or false package |
| package failure | `IntegrityFailed` / 50 | complete collection cannot override failed final verification; provisional record is not exposed |
| live concurrent launch | `NotStarted` / 20 | real separate process owns the device-wide mutex; second launch schedules nothing and owner exits normally |
| abandoned owner | `NotStarted` / 20 | real abandoned mutex enters cleanup-only recovery; collection does not resume |
| cleanup exception | `CleanupIncomplete` / 60 | cleanup failure overrides complete evidence; final protected record and terminal agree |
| cleanup deadline | `CleanupIncomplete` / 60 | an over-budget cleanup adapter is cancelled/stopped and residue stays uncertain |
| package deadline | `IntegrityFailed` / 50 | an over-budget finalizer is cancelled/stopped and no provisional record is exposed |

The focused test records first-progress time, maximum active heartbeat gap, and cancellation-acknowledgement time from a monotonic stopwatch. It asserts the five-second, ten-second, and two-second budgets respectively. The generated cancellation fixture exercises the actual named-event cooperative-cancellation path.

## Validation commands

```powershell
pwsh -NoLogo -NoProfile -File ./tests/RunLifecyclePolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/RunLifecycle.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/RunApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/BuildDeterminism.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

These tests require Windows for the device-wide named mutex, named cancellation event, Authenticode verification, suspended process creation, and Job Object process-tree control. They use only the installed stable PowerShell host and download no dependency.

## Safety boundary

- The lifecycle fixture is strict UTF-8, at most 1 KiB, has exactly two properties, and selects only a release-declared scenario.
- A fixture never supplies executable, command, script, argument, environment, evidence, finalizer, cleanup target, lock name, deadline, or exit code.
- Progress and terminal output use stable codes and omit raw adapter/process errors.
- The lock has no file path. Live ownership is never disturbed; abandoned ownership permits cleanup only.
- Cleanup exceptions and lock-release uncertainty remain `CleanupIncomplete`.
- Package failure remains `IntegrityFailed`; an unprotected provisional record is not emitted as completed evidence.
- The deterministic application embeds the lifecycle source, policy, schema, and exact resource digests.
