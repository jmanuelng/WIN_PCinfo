# Issue #69 validation projection

This public projection contains identifier-free release-gate, manifest, and matrix checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, Terraform material, Azure signing account, or protected evidence content.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. |
| Tool installation | None. |
| Elevation | None. |
| Authentication | None. |
| Azure resource change | None. Evaluation is offline and synthetic. |
| Push, merge, or release | Not performed by this implementation slice. |
| Destructive cleanup | Only ticket-owned temporary gate workspaces. |

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Policy contract | `tests/ReleaseGatesPolicy.Tests.ps1` requires `docs/spec/releases/2.0.0-preview.1-release-gates.json` to satisfy `schemas/release-gates.schema.json`. Support, Preview, publication, and capability-delivery claims stay false. Results are only Pass, ProductFail, InfrastructureInconclusive, NotRun, Expired, and Invalidated. |
| Decision engine | `tests/ReleaseGates.Tests.ps1` evaluates complete, missing, failed, expired, invalidated, mismatched-candidate, unsupported-runtime, locale, privacy, cleanup, waiver, and synthetic scenario packs. Missing or failed evidence blocks the claim and cannot be averaged or waived. |
| Derived matrix | The Preview Capability Matrix is generated from the frozen ledger and evidence. It is never a hand-edited strongest-case table. `Supported` is not emitted for Preview.1. |
| Quality budget | Three independent clean measurements are required. Binding 5/10/2-second interaction limits and the provisional memory, workspace, package, and report ceilings are enforced. One infrastructure replacement does not turn a product failure into a pass. |
| Public/private boundary | Public records omit workspace paths, Azure identifiers, credentials, Terraform state, and local user paths. Non-synthetic packs are rejected. |
| Generated-application seam | `tests/ReleaseGatesApplication.Tests.ps1` invokes `-Workflow EvaluateReleaseGates`. A complete synthetic pack completes with `RELEASE.GATES_EVALUATED`. A missing pack or a privacy-violating pack ends `NotStarted`. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/ReleaseGatesPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ReleaseGates.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ReleaseGatesApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
