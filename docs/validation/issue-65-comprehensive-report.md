# Issue #65 validation projection

This public projection contains release-owned report-contract checks and identifier-free synthetic validation results only. It contains no Assessment Record value, package path, device identifier, tenant fact, certificate fingerprint, proxy value, or protected evidence content.

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Deterministic report shell | `tests/ComprehensiveReport.Tests.ps1` renders the same synthetic record twice for `Completed`, `CompletedWithGaps`, `Cancelled`, `TimedOut`, `IntegrityFailed`, and `CleanupIncomplete` outcomes, exercises `en-US`, `es-MX`, `tr-TR`, `ja-JP`, and `ar-SA` locale fixtures, and drives a bounded maximum-size synthetic record while verifying byte-identical HTML, ordered executive-summary headings, scripting-free offline markup, visible keyboard-focus rules, and print CSS. |
| Generated application seam | `tests/ComprehensiveReportApplication.Tests.ps1` runs the generated artifact through `DirectOutbound`, `LocalOnly`, `Unicode`, and `Redirect` full-profile scenarios and verifies one sanitized `win-pcinfo.comprehensive-report-validation` record, one Completion Summary, one terminal record, deterministic report output, package-manifest consistency, and cleanup. |
| Package and summary agreement | The generated seam proves that the report, rendered completeness, manifest completeness, Completion Summary assessment fields, protected-package verification, cleanup state, terminal outcome, and result-sharing guidance stay aligned without exposing the package path or inner contents. |
| Offline and operability guardrails | The report verifier rejects external asset references, script markup, inline event handlers, and print-less or focus-less shells. Navigation is limited to internal anchors and a skip link. |
| Unicode and locale safety | The locale fixtures and Unicode scenarios prove that multilingual report content survives the UTF-8 HTML path without changing the deterministic contract or widening localized parsing. |

## Related regression coverage

- `tests/DeviceReadinessApplication.Tests.ps1` still completes the standalone device slice with one Completion Summary and one terminal record.
- `tests/CrossDomainGuidanceApplication.Tests.ps1` still derives the cautious migration path and verifies the report section without exposing Restricted evidence.

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/ComprehensiveReport.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ComprehensiveReportApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/DeviceReadinessApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/CrossDomainGuidanceApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
