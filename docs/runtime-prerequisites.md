# Runtime prerequisites and safe launch

This guide explains WIN-PCInfo v2 launch admission. It is for beginners as well as automation authors.

## What launch checks

The generated application normalizes a versioned Assessment Run Request, emits versioned progress records, and runs the local Runtime Compatibility Check. An approved, trusted candidate can continue from its frozen Preparation Summary through assessment, reporting and protected packaging. The [Guided Runway](guided-runway.md) describes GUI and console operation.

Runtime checking does not authorize collection. Assessment requires the trust and preparation gates and explicit approval. WIN-PCInfo never installs software or changes device configuration. A synthetic runtime-fixture option exists for automated security validation; it is marked in the terminal record and can never authorize live collection.

`NotStarted` and process exit code `20` describe admission failure or declined preparation:

- An eligible runtime alone does not establish application trust, destination safety or approval. An unsigned development artifact fails with `PREPARATION.INTEGRITY_FAILED` before collection.
- On an ineligible host, a `RUNTIME.*` reason identifies the failed check and the terminal record includes the official Microsoft installation page and a retry step.

This behavior does not create a Preview Release or a supported-capability claim.

## Required PowerShell host

The portable entry and shared generated-application test helper enumerate PATH
application matches in order, followed by the documented Program Files locations.
They deduplicate literal paths, reject unverified executables before execution,
and choose the first candidate that passes the generated application's
`CheckRuntime` workflow. This diagnostic workflow uses the exact policy below,
ignores assessment/fixture inputs, and never starts collection. Selection does
not install or repair a runtime. Tests may explicitly select an executable to
verify an incompatible host's public rejection contract.

The application initializes UTF-8 input/output even without an inherited console;
the existing UTF-8 test-host setup is retained. Runtime eligibility still requires
the strict encoding, module provenance, cryptography, and process checks below.

Use an already installed PowerShell host with all of these properties:

- `PSEdition` is `Core`.
- The version is stable PowerShell 7.6.0 or later in the 7.x family. Preview, release-candidate, daily, and PowerShell 8-or-later hosts are not eligible.
- The process architecture is x64, x86, or ARM64. Architecture eligibility is not the same as a Supported Scenario claim; support requires separate release evidence.
- Required Core commands and commands exported by the literal built-in Utility and Management modules are available with their expected identities.
- The Utility, Management, and Security module manifests and referenced binary payloads under the active runtime's literal `$PSHOME` tree have valid Microsoft Authenticode signatures, and `Microsoft.PowerShell.Utility\Test-Json` comes from that verified Utility module.
- Strict UTF-8 decoding, JSON Unicode round trips, UTF-8 standard output, SHA-256, AES-256-GCM, literal module loading, and bounded child-process start/wait/exit/hard-termination behavior work as expected.

These checks are the exact `win-pcinfo.runtime-compatibility/1.0.0` policy. That policy admits Core, stable versions from 7.6.0 up to but excluding 8.0.0, the three named architectures, and the named safety behavior. The range follows the governing decision that a newer stable 7.x host may attempt compatibility checks; passing does not create Release Evidence or a support claim for an unvalidated patch. A missing safety mechanism fails closed before assessment work instead of silently selecting a weaker fallback.

The module check trusts the installed PowerShell Security cmdlet and Windows Authenticode as its local trust anchor. A hostile replacement of the running PowerShell engine itself cannot be disproved by that same process; operators and release validation must separately verify the PowerShell installation and WIN-PCInfo release provenance. Any missing file, identity mismatch, invalid signature, untrusted signer, or ambiguous command makes the runtime ineligible.

After verification, the application invokes the exact `ConvertFrom-Json` and `ConvertTo-Json` command objects from that Utility module for request input and every structured output. It does not resolve those contract operations again through ambient functions, aliases, profiles, or module-path discovery.

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

The build reads the eleven tracked modules in a fixed order and writes `artifacts/WIN-PCInfo.ps1` as UTF-8 with BOM and CRLF line endings. Its versioned build-evidence object includes the build-tool digest, every source path and digest, and the generated SHA-256 digest. Identical source bytes produce identical application bytes regardless of the chosen output directory.

The generated file is ignored because it is reproducible. Review and edit files under `src/`, then rebuild; never hand-edit the artifact.

The same command also writes `artifacts/WIN-PCInfo-2.0.0-preview.1-portable.zip`. That archive is the unsigned portable package: the generated application, authenticated supporting resources, beginner documentation, checksums, dependency inventory, SPDX SBOM, and precursor provenance. It does not install PowerShell. First-run verification and the Windows PowerShell helper are documented in [Portable distribution and first-run](portable-distribution.md). The separately governed [Attested Preview](attested-preview.md) fallback may bind that unchanged zip only when Artifact Signing is not operational or during a verified service incident; it remains unsigned and cannot satisfy the Stable signing gate.

## Guided launch

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Mode Guided
```

The guided adapter constructs the current default request:

```json
{
  "contractVersion": "1.0.0",
  "profile": "ComprehensiveLocalAssessment",
  "outputDestination": "./WIN-PCInfo-Results",
  "networkBehavior": "LocalOnly",
  "updateChoice": "NoUpdateCheck",
  "diagnosticLevel": "Standard",
  "automationChoices": {
    "allowAssessmentNetwork": false,
    "allowElevation": true,
    "allowInstallation": false,
    "allowPersistentChanges": false,
    "allowStaleRecovery": false,
    "verificationOverride": "None"
  }
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
| `RUNTIME.ENCODING_INCOMPATIBLE` | Strict UTF-8 behavior did not pass. | Use an eligible stable PowerShell installation and retry. |
| `RUNTIME.CRYPTOGRAPHY_INCOMPATIBLE` | Required SHA-256 or AES-GCM behavior did not pass. | Use an eligible stable PowerShell installation and retry. |
| `RUNTIME.MODULE_LOADING_INCOMPATIBLE` | Literal built-in module loading did not pass. | Verify or repair PowerShell outside WIN-PCInfo, then retry. |
| `RUNTIME.PROCESS_CONTROL_INCOMPATIBLE` | Bounded child-process control did not pass. | Close modified sessions, verify the PowerShell installation, and retry. |
| `PREPARATION.INTEGRITY_FAILED` | Candidate trust or embedded integrity could not be proved. | Use the exact approved candidate; never bypass the gate. |

## Validate a contribution

Run all source-only and generated-artifact checks with no additional packages:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/Run-Tests.ps1
```

The suite exercises equivalent guided and automation launches, invalid automation requests, the runtime matrix, preservation of an isolated pre-existing working file, and deterministic build provenance. The live eligible-host path executes the real encoding, cryptographic, signed-module, and process-control probes; synthetic fixtures verify every stable terminal decision through the generated artifact. Fixtures contain synthetic compatibility flags only; they contain no assessment, tenant, account, device, network, or credential data.
