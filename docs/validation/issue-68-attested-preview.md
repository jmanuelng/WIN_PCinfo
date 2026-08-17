# Issue #68 validation projection

This public projection contains identifier-free attestation, warning, and tamper checks only. It contains no Assessment Record value, package path, device identifier, tenant fact, recipient fingerprint, Terraform material, Azure signing account, or protected evidence content.

## Observable evidence

| Gate | Public-safe result |
| --- | --- |
| Policy | `docs/spec/releases/2.0.0-preview.1-attested-preview.json` is closed by `schemas/attested-preview.schema.json`. Trust class is `AttestedPreview`. Signed, Trusted, Supported, and the Stable signing gate are permanently false. Fallback reasons are only `ArtifactSigningNotOperational` and `VerifiedServiceIncident`. |
| Bundle | `tests/AttestedPreview.Tests.ps1` builds twice, attests the unchanged portable zip, and requires identical attestation bytes, a frozen 1980-01-01 timestamp, and bindings for the candidate, application, manifest, checksums, inventory, SBOM, source revision, and build provenance. Convenience selection is rejected. |
| Warning | The bundle includes `LIMITED-TRUST.md`. Generated-application `-Workflow VerifyAttestation` emits `win-pcinfo.limited-trust-warning` as the first record before launch. |
| Verifier | `tests/AttestedPreviewApplication.Tests.ps1` verifies the clean bundle, then mutates the application, resource, manifest, checksum, provenance, source revision, and dependency inventory. Each class returns `NotStarted` with a typed `ATTESTATION.*` reason. Missing inputs, Trusted labels, convenience reasons, and a claimed Stable signing gate are rejected. Preparation fixtures cannot override the result. |
| Final identity | The attested unsigned portable package remains the final distributable identity. Checksums and provenance bind that unchanged zip. |

## Reproduce

Use stable PowerShell Core 7.6 or a later 7.x version:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/AttestedPreview.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/AttestedPreviewApplication.Tests.ps1
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```
