# Preparation Summary and approval

WIN-PCInfo prepares one complete plan before it can elevate, install anything, change Windows, contact a network service, collect evidence, or create an Evidence Workspace. The generated application prints one beginner-readable `win-pcinfo.preparation-summary`; its `plan` field contains the immutable plan so each disclosure appears once.

A trusted artifact's approval starts the frozen standard-user Device and Windows readiness operation, bounded Administrator firmware-readiness and effective-policy operations, locale-neutral standard-user identity operations, the standard-user resource-dependency and local-network-topology operations, and the predefined read-only SYSTEM MDM-provider operation. It validates their combined Assessment Record, renders the report, and finalizes the Protected Evidence Package. Decline remains `NotStarted` with `PREPARATION.DECLINED`. The repository's local development build is unsigned, so ordinary use fails `PREPARATION.INTEGRITY_FAILED`; closed fixtures exercise the generated path without claiming real device evidence. Fixtures remain closed and cannot widen collection, mutation, network access, identities, executable or script content.

## What the summary tells you

Review the whole summary once. It discloses:

- all 29 release-enabled Product Capabilities, including the selected profile scope, automatically added dependency `CAP-0015`, and release-wide product obligations;
- the single Privileged Collection Phase, maximum of one UAC interaction at the approval boundary, and restricted predefined SYSTEM work, with no later elevation choice or product prompt;
- stable PowerShell 7.6-or-later 7.x and built-in-module dependencies, with no planned install or agreement;
- estimated duration and disk use;
- the exact network behavior and planned request classes;
- the protected output destination, Local Package Protector, and a fixed zero-or-one Recipient Profile choice;
- Windows Feature observations, with no feature changes;
- limitations, later side effects, and cleanup work.
- the complete device-context collector/rule contract: structured readiness, activation, form, virtualization, chassis, battery, and power sources; standard-user context; offline behavior; signed executable; dependencies; deadlines; output/evidence bounds; and verified cleanup.
- the complete firmware-readiness collector/rule contract: exact firmware, BIOS/SMBIOS, Secure Boot, and TPM projections; Administrator context inside the one approved phase; offline and read-only behavior; dependencies; deadline/output bounds; follow-up discovery limits; and verified process/channel cleanup.
- the complete identity/enrollment contract: NetAPI domain and Entra join structures, Terminal Services Assessment User Context verification, the default work-or-school projection, the predefined LocalSystem MDM-provider source, Restricted identifier fields, offline/no-authentication behavior, finite bounds, four tenant-side questions, and verified SYSTEM cleanup.
- the direct local-administrator contract: locale-neutral built-in group selection by well-known SID, direct-only bounded membership, Administrator execution, no nested expansion or mutation, Restricted identifiers, finite output/deadline bounds, and advisory-only interpretation.
- the effective-policy contract: cached RSoP, local SAM, Audit Policy, direct LSA rights, and configured registry signals under exact Administrator/offline/read-only bounds.
- the resource-dependency contract: Assessment User-bound mapped resources, UNC connections, printers, drivers, and common peripheral classes; exact local sources; eight-entry category bounds; no remote/content/credential access; and advisory-only migration interpretation.
- the local-network-topology contract: adapters, Windows connection profiles, IP configuration, active routes, configured resolvers and proxy, VPN/security registrations, and bounded existing local connections; exact offline sources; eight-entry scope bounds; three named network-dependent probes held `NotAttempted` by Local Only; and no traffic, packet capture, credential collection, health inference, or network change.

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

To select one Package Recipient in Automation, add the `recipientSelection` object described in [Recipient Profiles and restricted report export](recipient-sharing.md). Guided mode accepts the paired `-AssessmentRecipientProfilePath` and `-AssessmentRecipientFingerprintConfirmation` parameters; omit both for zero recipients. Preparation validates the public profile and requires the separately confirmed SHA-256 fingerprint before the summary can become ready. The summary shows the recipient label, fingerprint, and actual protection level but never the local profile path.

Omit `-AcceptPreparation` to decline. The switch cannot repair an invalid request, missing prerequisite, or integrity failure. It cannot approve later input, new authority, a new agreement, another elevation, or a recipient change; those require a new request and plan.

The immutable output contract is documented by [`schemas/preparation-plan.schema.json`](../schemas/preparation-plan.schema.json). Hidden Device Readiness and Identity/Enrollment scenarios can cross approval only through their separate generated validation seams; they cannot supply evidence, identifiers, or authority.

The post-approval Privileged Collection Plan is explained in [Privileged Collection Plan](privileged-collection-plan.md). Its one LocalSystem operation is further reduced to the separate [SYSTEM Collection Sub-plan](system-collection-sub-plan.md). Both synthetic fixture families are validation-only and do not change the ordinary Preparation prerequisites.
