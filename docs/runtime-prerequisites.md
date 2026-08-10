# Runtime prerequisites and safe launch

This guide explains the first WIN-PCInfo v2 launch slice. It is for beginners as well as automation authors.

## What this slice does

The generated application normalizes a versioned Assessment Run Request, emits versioned progress records, and runs the local Runtime Compatibility Check. It then stops at the preparation boundary because assessment collection is not part of this slice.

No launch in this slice collects device evidence, makes an assessment network request, requests elevation, installs software, changes a Windows Feature, or changes device configuration. A synthetic runtime-fixture option exists for automated security validation; it is marked in the terminal record and can never authorize collection.

`NotStarted` and process exit code `20` are therefore expected for both eligible and ineligible hosts:

- On an eligible host, reason `SLICE.COLLECTION_NOT_IMPLEMENTED` means the runtime passed and the application reached the next safe boundary.
- On an ineligible host, a `RUNTIME.*` reason identifies the failed check and the terminal record includes the official Microsoft installation page and a retry step.

This behavior does not create a Preview Release or a supported-capability claim.

## Required PowerShell host

Use an already installed PowerShell host with all of these properties:

- `PSEdition` is `Core`.
- The version is stable PowerShell 7.6.0 or later in the 7.x family. Preview, release-candidate, daily, and PowerShell 8-or-later hosts are not eligible.
- The process architecture is x64, x86, or ARM64. Architecture eligibility is not the same as a Supported Scenario claim; support requires separate release evidence.
- Required built-in commands are available.
- the built-in `Microsoft.PowerShell.Utility\Test-Json` validator resolves from the active runtime's literal `$PSHOME` module tree;
- strict UTF-8 behavior, SHA-256, AES-256-GCM, literal built-in module loading, and bounded child-process start/wait/exit/termination behavior work as expected.

These checks protect later evidence, validation, module, and process boundaries. A missing safety mechanism fails closed before assessment work instead of silently selecting a weaker fallback.

## Install PowerShell yourself when needed

WIN-PCInfo never installs, upgrades, downgrades, repairs, or changes PowerShell. Follow Microsoft's [Installing PowerShell on Windows](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows) instructions, choose a stable PowerShell 7 release, and complete any installation decisions yourself.

Open a new terminal and verify the result:

```powershell
pwsh -NoLogo -NoProfile -Command '$PSVersionTable | Select-Object PSEdition, PSVersion'
```

Confirm that `PSEdition` is `Core` and the version is at least `7.6.0` but still begins with `7`. Then retry the same WIN-PCInfo command.

## Build the generated application

Clone or download the repository, open it in stable PowerShell 7.6-or-later, and run:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
```

The build reads the six tracked modules in a fixed order and writes `artifacts/WIN-PCInfo.ps1` as UTF-8 with BOM and CRLF line endings. Its versioned build-evidence object includes the build-tool digest, every source path and digest, and the generated SHA-256 digest. Identical source bytes produce identical application bytes regardless of the chosen output directory.

The generated file is ignored because it is reproducible. Review and edit files under `src/`, then rebuild; never hand-edit the artifact.

## Guided launch

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Mode Guided
```

The guided adapter constructs the current default request:

```json
{
  "contractVersion": "1.0.0",
  "profile": "ComprehensiveLocalAssessment",
  "networkMode": "LocalOnly",
  "acceptPreparation": false
}
```

## Automation launch

Save that JSON as `request.json`, then run:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Mode Automation -RequestPath ./request.json
$LASTEXITCODE
```

Equivalent guided and automation inputs produce the same request digest and use the same progress, terminal-outcome, reason, and exit-code contracts. Automation requests reject missing fields, unknown fields, unsupported contract versions, unsupported profiles or network modes, and invalid field types before collection. Automation never falls back to an interactive prompt.

Each line on standard output is one JSON contract record. The final record is authoritative. Human-facing tools may explain those records, but localized wording must never become an automation input.

## Understand a stopped launch

All current paths end as `NotStarted` / `20`. Common stable reasons are:

| Reason | What it means | Safe next step |
| --- | --- | --- |
| `RUNTIME.HOST_MISSING` | No eligible PowerShell host was described or found. | Install stable PowerShell 7.6-or-later 7.x from Microsoft and retry. |
| `RUNTIME.EDITION_UNSUPPORTED` | The active host is not PowerShell Core. | Start `pwsh`, not Windows PowerShell, and retry. |
| `RUNTIME.PRERELEASE_UNSUPPORTED` | The host is a preview or other prerelease. | Install or select a stable 7.x release and retry. |
| `RUNTIME.VERSION_TOO_OLD` | PowerShell is earlier than 7.6.0. | Install a current stable 7.x release and retry. |
| `RUNTIME.MAJOR_UNSUPPORTED` | The host is not PowerShell 7. | Select stable PowerShell 7.6-or-later 7.x and retry. |
| `RUNTIME.ARCHITECTURE_UNSUPPORTED` | The process architecture is outside x64, x86, and ARM64. | Install an eligible PowerShell architecture and retry. |
| `RUNTIME.REQUIRED_COMMAND_MISSING` | A release-required built-in command is unavailable. | Repair or replace PowerShell outside WIN-PCInfo, then retry. |
| `RUNTIME.VALIDATOR_PROVENANCE_INVALID` | `Test-Json` did not resolve from the trusted built-in module location. | Close modified sessions, use `-NoProfile`, verify the PowerShell installation, and retry. |
| `RUNTIME.ENCODING_INCOMPATIBLE` | Strict UTF-8 behavior did not pass. | Use a supported stable PowerShell installation and retry. |
| `RUNTIME.CRYPTOGRAPHY_INCOMPATIBLE` | Required SHA-256 or AES-GCM behavior did not pass. | Use a supported stable PowerShell installation and retry. |
| `RUNTIME.MODULE_LOADING_INCOMPATIBLE` | Literal built-in module loading did not pass. | Verify or repair PowerShell outside WIN-PCInfo, then retry. |
| `RUNTIME.PROCESS_CONTROL_INCOMPATIBLE` | Bounded child-process control did not pass. | Close modified sessions, verify the PowerShell installation, and retry. |
| `SLICE.COLLECTION_NOT_IMPLEMENTED` | Runtime checks passed; this tracer bullet intentionally stops before collection. | Wait for the dependent assessment slice; do not treat this as completed assessment evidence. |

## Validate a contribution

Run all source-only and generated-artifact checks with no additional packages:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

The suite exercises equivalent guided and automation launches, invalid automation requests, the runtime matrix, the no-mutation boundary, and deterministic build provenance. Fixtures contain synthetic compatibility flags only; they contain no assessment, tenant, account, device, network, or credential data.
