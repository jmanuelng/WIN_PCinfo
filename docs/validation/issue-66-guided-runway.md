# Issue #66 validation projection

This public projection contains identifier-free documentation-contract and Help/About checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, or protected evidence content.

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Content contract | `tests/GuidedRunwayPolicy.Tests.ps1` validates `docs/spec/releases/2.0.0-preview.1-guided-runway.json` against `schemas/guided-runway.schema.json` and locks the Choose through Share runway, required topics, claim separations, synthetic examples, operator procedures, Field Validation consent, and passive discovery rules. |
| Documentation walkthrough | `tests/GuidedRunwayDocumentation.Tests.ps1` requires the Guided Runway, Consultant Workbench, Field Validation, synthetic examples, SECURITY, CONTRIBUTING, and README files, resolves local markdown links, checks documented `pwsh -NoLogo -NoProfile -File` commands against implemented Workflow and Mode values, and rejects deferred behaviors claimed as implemented. |
| Passive Help/About | `tests/ProductHelp.Tests.ps1` and `tests/ProductHelpApplication.Tests.ps1` open `-Workflow Help` and `-Workflow About` on the generated unsigned artifact, emit one `win-pcinfo.product-help` record with repository, feedback, contribution, and private vulnerability-reporting routes, and prove that declined and synthetic full-profile assessment runs emit no Help record and no feedback prompt. |
| Privacy review | Help and About records contain no device, package, tenant, fingerprint, or address fields. Field Validation instructions require the exact consent phrase `I CONSENT TO A PRIVACY-SANITIZED FIELD VALIDATION ATTESTATION` and state that ordinary Preview use never becomes validation evidence automatically. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/GuidedRunwayPolicy.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/GuidedRunwayDocumentation.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ProductHelp.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/ProductHelpApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
