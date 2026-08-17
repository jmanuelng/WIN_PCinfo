# Issue #67 validation projection

This public projection contains identifier-free build, inventory, and first-run checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, Terraform material, or protected evidence content.

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Deterministic package | `tests/PortableDistribution.Tests.ps1` builds twice from clean independent work areas and requires byte-identical zip archives, matching unsigned generated-content and unsigned portable-package identities, UTF-8/LF resource identities, SPDX 2.3, a frozen dependency inventory, and a 1980-01-01 precursor timestamp. |
| Inventory and notices | The extracted package contains the generated application, helper, FIRST-RUN page, NOTICE, checksums, dependency inventory, SPDX SBOM, and precursor provenance. Every listed resource has a normalized path, exact digest, license, and provenance. The package records `installsRuntime: false`. |
| Privacy boundary | Archive bytes and in-package JSON are scanned for user profile paths, UNC paths, tenant or subscription markers, private keys, Terraform material, and cloud access keys. |
| First-run seam | `tests/PortableDistributionApplication.Tests.ps1` extracts the zip to two locations and runs `-Workflow Verify` plus Help on the generated application. Mutation of each protected class, and a missing schema, return `NotStarted` / `PREPARATION.INTEGRITY_FAILED` with no fixture override. |
| Runtime paths | Direct Windows PowerShell invocation of the generated application still returns `RUNTIME.EDITION_UNSUPPORTED`. The package helper relaunches eligible `pwsh` or returns `RUNTIME.HOST_MISSING` with Microsoft's installation URL. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/PortableDistribution.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/PortableDistributionApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/BuildDeterminism.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
