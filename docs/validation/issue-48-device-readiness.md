# Issue #48 Device Readiness validation evidence

This page records public-safe, identifier-free validation for the narrow Device and Windows readiness slice. It contains no real Assessment Record, report, package, device value, path, user, or environment fact.

## Generated-application matrix

`tests/DeviceReadinessApplication.Tests.ps1` proves the complete vertical slice through the generated public application. The original partial, unavailable, malformed, oversize, virtual, Unicode, and non-English scenarios remain a tested subset of the expanded issue #49 matrix. See [Issue #49 validation evidence](issue-49-activation-form-power.md) for current behavior.

The assertions cover:

- exactly one sanitized scenario result and one terminal result;
- stable `Completed` or `CompletedWithGaps` exit mapping;
- explicit complete, partial, unavailable, or malformed coverage;
- `Indeterminate` whenever readiness evidence is incomplete;
- canonical Assessment Contract acceptance where a record is possible;
- beginner report verification and Protected Package reopen where applicable;
- absence of restricted synthetic value markers in stdout and stderr; and
- exact removal of the test-owned package and workspace boundary.

Run from the repository root with stable PowerShell 7.6 or later 7.x:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessScenarios.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessContract.Tests.ps1
```

The fixture files select only a release-owned scenario. Synthetic record/report/package samples are created inside an ignored, run-owned validation boundary, validated in memory, and deleted before the generated application reports cleanup success. Private samples are intentionally not committed or attached to the public issue.

The final repository validation ran all 37 `*.Tests.ps1` scripts successfully. The deterministic-build check also executed a relocated generated artifact, proving that its embedded Device Readiness policy does not depend on a repository sidecar. Independent Spec and Standards/domain reviews reported zero findings. The ignored generated artifact and its deterministic-build scratch directory were then removed; no Device Readiness validation boundary remained.

## Coverage map

| Requirement | Public evidence |
|---|---|
| Structured bounded Windows sources | Release policy, approved collector catalog, and focused policy test |
| Explicit fields, provenance, sensitivity, states, coverage, and bounds | Assessment Contract Set and generated complete/partial cases |
| Evidence-gated advisory rule | Focused two-pass contract test plus partial, unavailable, malformed, and oversize generated cases remain `Indeterminate` |
| Beginner report and canonical package | Complete case validates report markers and reopens both packaged artifacts |
| Restricted values stay private | Every generated case scans stdout and stderr for synthetic identifying markers |
| Generated public application and cleanup | Both generated-application suites verify stable terminal output and boundary absence |
| Frozen collector and rule operations | Preparation Plan includes both bounded operations in the embedded Device Readiness policy before approval |
