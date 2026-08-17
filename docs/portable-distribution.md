# Portable distribution and first-run

This guide explains the unsigned portable package produced by the deterministic build. Completing these steps does not create a Preview or Supported claim.

The package is a precursor identity. It is not the later timestamped signed distributable.

## What the package contains

One reproducible archive holds:

- the generated primary application `WIN-PCInfo.ps1`
- explicit schemas, catalogs, definitions, helpers, and beginner documentation
- exact checksums, a dependency inventory, an SPDX SBOM, and unsigned precursor provenance
- a Windows PowerShell helper that can only locate eligible PowerShell 7 or give official retry guidance

The package does not install, upgrade, downgrade, or repair PowerShell.

## Build the package

From a repository checkout, using an already installed stable PowerShell 7.6 or later 7.x host:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
```

The build writes the ignored generated application and the ignored portable archive:

- `artifacts/WIN-PCInfo.ps1`
- `artifacts/WIN-PCInfo-2.0.0-preview.1-portable.zip`
- `artifacts/WIN-PCInfo-2.0.0-preview.1/`

The returned build evidence includes two precursor identities: the SHA-256 of the generated application and the SHA-256 of the zip. Identical source bytes produce identical identities.

Do not hand-edit the generated application or the extracted package files.

## Extract and verify

Extract the zip to a local folder you control. Then run first-run verification through the generated application:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo-2.0.0-preview.1/WIN-PCInfo.ps1 -Workflow Verify
```

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo-2.0.0-preview.1/WIN-PCInfo.ps1 -Workflow Help
```

A missing, altered, substituted, or unauthenticated governing resource returns `NotStarted` with `PREPARATION.INTEGRITY_FAILED`. Preparation fixtures cannot override that result.

## Windows PowerShell helper

The extracted `Start-WIN-PCInfo.ps1` helper is not the assessment engine. On Windows PowerShell 5.1 it may only find `pwsh` and relaunch the generated application, or print Microsoft's installation URL and stop.

Invoking `WIN-PCInfo.ps1` directly with Windows PowerShell still returns `RUNTIME.EDITION_UNSUPPORTED`. That is intentional: the generated application does not relaunch from the wrong host.

## Trust separations

- Package checksums and the unsigned precursor identities are not Authenticode.
- An eligible PowerShell host is not a Supported Windows scenario.
- This local unsigned package is not itself an Attested Preview and not a trusted release. The separately governed fallback is documented in [Attested Preview trust bundle](attested-preview.md).

See the [Guided Runway](guided-runway.md) Verify stage and [Runtime prerequisites](runtime-prerequisites.md) for the remaining trust questions.
