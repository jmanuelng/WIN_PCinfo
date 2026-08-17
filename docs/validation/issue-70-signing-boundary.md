# Issue #70 validation projection

This public projection contains identifier-free Signing Boundary, eligibility, verification, and cleanup checks only. It contains no Assessment Record value, package path, device identifier, recipient fingerprint, Terraform material, Azure signing account, certificate profile, transaction identifier, or protected evidence content.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. |
| Tool installation | None. Live signing clients are not acquired. |
| Elevation | None. |
| Authentication | None. |
| Azure resource change | None. The temporary Release Signing Session role is not predeclared, so the live path is `NotStarted`. |
| Other external-service changes | None. |
| Push, merge, or release | Not performed by this implementation slice. |
| Destructive cleanup | Only ticket-owned temporary signing workspaces and synthetic session markers. |
| Human-only actions | Digest confirmation is a required request field. Live signing approval remains outside this slice. |

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Policy contract | `tests/SigningBoundaryPolicy.Tests.ps1` requires `docs/spec/releases/2.0.0-preview.1-signing-boundary.json` to satisfy `schemas/signing-boundary.schema.json`. Support, Preview, publication, Trusted publication, and capability-delivery claims stay false. |
| Decision engine | `tests/SigningBoundary.Tests.ps1` exercises eligible signing, wrong digest, changed content, invalid or missing signature, timestamp failure, permission denial, service unavailability, unexpected signature, wrong candidate, gates not passed, missing approval, setup-authority absence, session cleanup, and final-package rebuild. |
| Generated-application seam | `tests/SigningBoundaryApplication.Tests.ps1` invokes `-Workflow SignAndVerifyCandidate`. A bound eligible request completes with `SIGNING.SIGNED_AND_VERIFIED`. Fail-closed cases stay `NotStarted` and cannot be published as Trusted. |
| Live Azure path | Without setup authority the path is `NotStarted` / `SIGNING.SETUP_AUTHORITY_REQUIRED`. A genuine outage is `AttestedFallbackEligible` and does not satisfy the Stable signing gate. |
| Public/private boundary | Public records omit workspace paths, Azure identifiers, credentials, and local user paths. Non-synthetic requests are rejected. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/SigningBoundaryPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SigningBoundary.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/SigningBoundaryApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
