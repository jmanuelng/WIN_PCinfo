# Issue #72 validation projection

This public projection contains identifier-free controller, guest-control, cleanup, and Zero Round Residue checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, Terraform state, Azure resource ID, gallery identifier, host-network fact, or protected evidence content.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public policy, schemas, controller, tests, fixtures, and beginner docs. |
| Dependency acquisition | None. Terraform 1.12.2 and hashicorp/azurerm 4.37.0 remain declared-not-acquired. |
| Tool installation | None. |
| Elevation | None. |
| Authentication | Approved managed identity unavailable on this controller host. Live path `NotStarted`. |
| Azure resource change | None. Live create is blocked before side effects. |
| Push, merge, or release | Not performed by this implementation slice. |
| Destructive cleanup | Only ticket-owned temporary private workspaces and synthetic residue. |

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Policy contract | `tests/AzureValidationRoundPolicy.Tests.ps1` requires `docs/spec/releases/2.0.0-preview.1-azure-validation-round.json` to satisfy `schemas/azure-validation-round.schema.json`. Support, Preview, capability-delivery, and qualifying-evidence claims stay false. Trust class is `ControllerDevTracer`. |
| Controller | `tests/AzureValidationRound.Tests.ps1` runs cleanup-first admission, synthetic create, VM Agent readiness, candidate and payload verification, Local Only and approved egress, sanitized retrieval, teardown, and exact absence checks. A product failure still reaches zero residue. Remaining residue blocks completion, state removal, and rendered-file removal. A four-client or non-claiming plan is refused before create. Synthetic outcomes keep `azureContacted` false. |
| Live identity | `Test-AzureValidationRoundLiveIdentity` and the generated application without a fixture return `VALIDATION.IDENTITY_UNAVAILABLE` / `NotStarted` when the approved managed identity is absent. An `IDENTITY_ENDPOINT` without acquired pinned tooling returns `VALIDATION.TOOLING_UNRESOLVED` and still creates nothing. |
| Public/private boundary | Sanitized outcomes omit workspace paths, subscription paths, tenant facts, gallery IDs, IPs, Terraform paths, and credentials. Recovery journals and rendered admission files stay in the private workspace until zero residue. |
| Generated-application seam | `tests/AzureValidationRoundApplication.Tests.ps1` invokes `-Workflow RunValidationRound`. A complete synthetic fixture completes with `VALIDATION.ZERO_RESIDUE_PROVEN`. A product failure ends `CompletedWithGaps` after cleanup. Remaining residue ends `CleanupIncomplete`. Missing identity ends `NotStarted`. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationRoundPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationRound.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationRoundApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
