# Preparation Summary and approval

WIN-PCInfo prepares one complete plan before it can elevate, install anything, change Windows, contact a network service, collect evidence, or create an Evidence Workspace. The generated application prints one beginner-readable `win-pcinfo.preparation-summary`; its `plan` field contains the immutable plan so each disclosure appears once.

This implementation slice stops before collection. A trusted artifact's approval and decline both end as `NotStarted` with exit code `20`; approval reaches the next unimplemented execution boundary, while decline returns `PREPARATION.DECLINED`. The repository's local development build is unsigned, so normal use fails `PREPARATION.INTEGRITY_FAILED` before a summary. Synthetic tests model a trusted artifact only in validation-only runs, which end as `PREPARATION.VALIDATION_ONLY` and can never collect.

## What the summary tells you

Review the whole summary once. It discloses:

- all 29 release-enabled Product Capabilities, including the selected profile scope, automatically added dependency `CAP-0015`, and release-wide product obligations;
- the single frozen administrator boundary, maximum of one UAC interaction at the approval boundary, and restricted predefined SYSTEM work, with no later elevation choice or product prompt;
- stable PowerShell 7.6-or-later 7.x and built-in-module dependencies, with no planned install or agreement;
- estimated duration and disk use;
- the exact network behavior and planned request classes;
- the protected output destination, Local Package Protector, and fixed zero-recipient choice;
- Windows Feature observations, with no feature changes;
- limitations, later side effects, and cleanup work.

The plan digest appears with the summary and terminal record. If the request or any governed scope changes, the digest changes and the old approval cannot apply. The plan records the absolute local destination resolved during preflight, not a relative path that could later move. Preparation rejects UNC and mapped-network storage before readiness/free-space access, then checks output-path eligibility, required free disk, Local Package Protector availability, the recipient choice, and the no-Windows-Feature-change boundary without creating files. Missing critical prerequisites return `PREPARATION.PREREQUISITE_UNRESOLVED`. An unsigned or invalidly signed application, corrupt embedded release definition, or invalid application manifest returns `PREPARATION.INTEGRITY_FAILED`; there is no **Run Anyway** path for a digest, manifest, signature, attestation, or governing-resource failure.

## Choose network behavior

`LocalOnly` plans zero assessment network requests. Network-dependent capabilities remain visible and later report honest unavailable or not-attempted coverage.

`MicrosoftConnectivityEnabled` plans only release-bound DNS and TCP/TLS/HTTP reachability tests for named Microsoft management and security services. It does not allow automatic telemetry, authenticated Microsoft cloud collection, tenant API access, arbitrary internet access, Azure resource changes, or device network reconfiguration.

In automation, `networkBehavior` and `automationChoices.allowAssessmentNetwork` must agree. Conflicting or unknown security-sensitive input fails before preparation.

## Guided approval

Build and inspect the fail-closed development path with stable PowerShell Core 7.6 or later 7.x. A future trusted release artifact uses the same command and can reach the summary after all prerequisites, including the Local Package Protector, are present:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Mode Guided
```

After reading the emitted Preparation Summary, type exactly `APPROVE` and press Enter. Any other input, empty input, or end-of-input declines safely. Approval is requested only after the summary.

## Automation approval

Start from [`tests/fixtures/automation-request.json`](../tests/fixtures/automation-request.json) for Local Only or [`tests/fixtures/automation-request-connectivity.json`](../tests/fixtures/automation-request-connectivity.json) for Microsoft Connectivity Enabled. The public request schema is [`schemas/assessment-run-request.schema.json`](../schemas/assessment-run-request.schema.json).

For a trusted release artifact with every prerequisite present, approval requires the separate switch in addition to the validated request:

```powershell
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 `
  -Mode Automation `
  -RequestPath ./tests/fixtures/automation-request.json `
  -AcceptPreparation
```

Omit `-AcceptPreparation` to decline. The switch cannot repair an invalid request, missing prerequisite, or integrity failure. It cannot approve later input, new authority, a new agreement, another elevation, or a recipient change; those require a new request and plan.

The immutable output contract is documented by [`schemas/preparation-plan.schema.json`](../schemas/preparation-plan.schema.json). Hidden runtime and preparation fixtures are for synthetic validation only and always stop before collection.
