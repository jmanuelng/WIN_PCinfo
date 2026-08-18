# Issue #73 validation projection

This public projection contains identifier-free lease, cancellation, expiry, recovery, and four-client admission checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, Terraform state, Azure resource ID, gallery identifier, host-network fact, or protected evidence content.

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
| Policy contract | `tests/AzureValidationRoundPolicy.Tests.ps1` requires a four-client ceiling, a six-hour hard expiry, a 30-minute Cleanup Reserve, an exclusive lease, irreversible Round Cleanup Mode, independent recovery, and seven-day completed-record retention. Support, Preview, and capability-delivery claims stay false. |
| Exclusive lease and recount | `tests/AzureValidationRoundSafety.Tests.ps1` holds one lease, recounts live tagged validation VMs, admits four, and rejects a request whose resulting total exceeds four. A busy lease and Cleanup Pending also reject before create. |
| Cancellation and expiry | The same module tests inject cancellation during create, readiness, transfer, execution, retrieval, and teardown, and simulate expiry and Cleanup Reserve. Each path enters Round Cleanup Mode, stops new tests and evidence export, and still reaches independently verified zero residue without becoming a product pass. |
| Independent recovery | Host-loss and `RecoverValidationRound` fixtures complete cleanup from the private Round Recovery Record after local journal files are gone. Cleanup is idempotent and never deletes an unresolved or unrelated token. |
| Generated-application seam | `tests/AzureValidationRoundApplication.Tests.ps1` runs a four-client synthetic round to `VALIDATION.ZERO_RESIDUE_PROVEN`, cancellation and host-loss fixtures to `CompletedWithGaps`, independent recovery through `-Workflow RecoverValidationRound`, and Cleanup Pending as `NotStarted`. Live Azure without identity stays `NotStarted`. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationRoundPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationRound.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationRoundSafety.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationRoundApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
