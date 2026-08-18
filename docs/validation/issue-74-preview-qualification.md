# Issue #74 validation projection

This public projection contains identifier-free Preview qualification, decision-packet, and final-artifact checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, Terraform material, Azure signing account, exact tested Windows build, or protected evidence content.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. |
| Tool installation | None. |
| Elevation | None. |
| Authentication | Approved Azure managed identity unavailable on this controller host. Live path `NotStarted`. |
| Azure resource change | None. Live create is blocked before side effects. |
| Other external-service changes | None. |
| Push, merge, or release | Not performed by this implementation slice. |
| Destructive cleanup | Only ticket-owned temporary private workspaces and synthetic residue. |
| Human-only actions | Accept or reject the final decision packet. Product failures cannot be waived. |

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Policy contract | `tests/PreviewQualificationPolicy.Tests.ps1` requires `docs/spec/releases/2.0.0-preview.1-preview-qualification.json` to satisfy `schemas/preview-qualification.schema.json`. Support, Preview, publication, and capability-delivery claims stay false. |
| Decision engine | `tests/PreviewQualification.Tests.ps1` evaluates complete signed and attested packs plus missing, failed, expired, invalidated, wrong-candidate, privacy-unsafe, cleanup-pending, waived, Azure-overclaim, attested-convenience, unsigned-as-final, and live-validation requests. Missing or failed evidence produces a denial packet and cannot be averaged or waived. |
| Generated-application seam | `tests/PreviewQualificationApplication.Tests.ps1` invokes `-Workflow QualifyPreviewCandidate`. A bound complete request finishes with `QUALIFY.APPROVED`. A missing request or a privacy-violating request ends `NotStarted`. Help smoke runs; collection does not start. |
| Live Azure path | Without the approved managed identity the path is `NotStarted`. A request that claims live Azure already started is denied. |
| Public/private boundary | Public records omit workspace paths, Azure identifiers, credentials, exact builds, and local user paths. Non-synthetic requests are rejected. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/PreviewQualificationPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PreviewQualification.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PreviewQualificationApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
