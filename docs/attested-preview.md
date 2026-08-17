# Attested Preview trust bundle

This guide explains the governed unsigned Preview fallback. Completing these steps does not create a Preview or Supported claim.

## UNSIGNED LIMITED-TRUST WARNING

This Attested Preview is **not Trusted**, **not signed**, **not Supported**, and **not Authenticode**. It cannot satisfy the Stable signing gate.

Use it only when Azure Artifact Signing is genuinely not operational or during a recorded verified service incident. Never select this fallback for convenience. The [Signing Boundary](signing-boundary.md) is the governed signing path; a genuine outage follows this Attested Preview contract and never silently weakens Stable.

## What the bundle is

The ordinary deterministic build still writes an unsigned portable zip. That zip is a precursor identity.

When the governed fallback is selected, the **same unchanged zip** becomes the final distributable identity. A sidecar trust bundle binds that exact candidate to:

- the zip digest
- the generated application digest
- the resource manifest
- checksums
- the dependency inventory
- the SPDX SBOM
- the content-tree source revision
- build provenance and the build-tool identity

The bundle does not resign the package and does not rewrite the zip.

## When fallback may be selected

The attestation entry script admits only two reasons:

- `ArtifactSigningNotOperational`
- `VerifiedServiceIncident`

A convenience reason is rejected before any bundle is written.

## Create the bundle

Build the portable candidate first, then attest it with one governed reason:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
pwsh -NoLogo -NoProfile -File ./build/Attest-Preview.ps1 -FallbackReason ArtifactSigningNotOperational
```

The command writes `artifacts/WIN-PCInfo-2.0.0-preview.1-attested-preview/attestation.json` and `LIMITED-TRUST.md` next to the unchanged zip.

## Verify before later work

Verification runs through the generated application. The first record is the unsigned limited-trust warning. A clean bundle then reports `ATTESTATION.VERIFIED`. Only that exact verified candidate may proceed to later smoke or validation work.

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Workflow VerifyAttestation -AttestationBundlePath ./artifacts/WIN-PCInfo-2.0.0-preview.1-attested-preview -CandidateArchivePath ./artifacts/WIN-PCInfo-2.0.0-preview.1-portable.zip
```

A missing, conflicting, substituted, or altered application, resource, manifest, checksum, provenance, source revision, dependency inventory, SBOM, or limited-trust warning page returns `NotStarted` with a typed `ATTESTATION.*` reason. There is no run-anyway switch. Preparation fixtures cannot override the result. Ordinary Help, About, Verify, and Assessment launches are not this fallback and do not inherit the warning.

## What this is not

- It is not Authenticode and not a Trusted release.
- It cannot satisfy the Stable signing gate.
- It does not install, upgrade, or repair PowerShell.
- A local unsigned development build without this governed selection is simply unsigned.

See the [Guided Runway](guided-runway.md) Attested versus trusted heading and [Portable distribution and first-run](portable-distribution.md) for the precursor package.
