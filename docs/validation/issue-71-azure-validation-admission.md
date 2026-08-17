# Issue #71 validation projection

This public projection contains identifier-free admission, template, and generated-application checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, Terraform state, or protected evidence content.

## Opening authorization checkpoint

| Category | Resolution |
| --- | --- |
| Repository writes | Ticket-owned public templates, controller, schemas, tests, and beginner docs. |
| Dependency acquisition | None. Terraform 1.12.2 and hashicorp/azurerm 4.37.0 are declared identities only. |
| Tool installation | None. This slice does not download or install Terraform, Azure CLI, or providers. |
| Elevation | None. |
| Authentication | None. Azure authentication is neither required nor used. |
| Azure resource change | None. Admission is offline. |
| Push, merge, or release | Not performed by this implementation slice. |
| Destructive cleanup | Only ticket-owned temporary private workspaces. |

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Policy contract | `tests/AzureValidationAdmissionPolicy.Tests.ps1` requires the release policy to satisfy `schemas/azure-validation-admission.schema.json`, pin one-to-four small clients, a six-hour ceiling, Standard SSD, Trusted Launch, no VM public IP, and `azureContact: None`. |
| Offline admission | `tests/AzureValidationAdmission.Tests.ps1` admits synthetic one-client and four-client plans, admits a non-claiming diagnostic VM, binds admitted SKUs, security, and required tags into the private `generated.auto.tfvars`, and rejects a fifth client, over-budget lifetime, missing cleanup reserve, expiry mismatch, wrong request kind, marketplace image, repository path, public path, UNC path, redirected folder, missing marker, floating provider version, live plan request, missing tags, public IP, transitive peering, Basic NAT IP, Premium disk, claiming non-Trusted-Launch Windows 11, and oversized SKU. |
| Public/private boundary | Rendered `generated.auto.tfvars` exists only in the marked private workspace. The sanitized verdict contains no workspace path, subscription path, tenant, gallery, IP, or profile path. |
| Generated-application seam | `tests/AzureValidationAdmissionApplication.Tests.ps1` invokes `-Workflow AdmitValidationRound` on the generated application. A one-client plan completes with `VALIDATION.ROUND_ADMITTED`. A fifth client and an in-repository workspace end `NotStarted` without rendering. |
| Tool provenance | Policy records Terraform 1.12.2 / BUSL-1.1 and hashicorp/azurerm 4.37.0 / MPL-2.0 as `declared-not-acquired`. No binary is downloaded by this ticket. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationAdmissionPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationAdmission.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AzureValidationAdmissionApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
