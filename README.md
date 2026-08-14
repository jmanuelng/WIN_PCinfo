# WIN-PCInfo

WIN-PCInfo is being rebuilt as a safe, modular Windows assessment application. The current v2 tracer bullets provide a generated launch path, verify the active PowerShell host, present one complete Preparation Summary **before any assessment collection or device change can begin**, collect narrow Device, Windows, firmware-security, domain/Entra registration, Assessment User Context, work-or-school, enrollment, direct local-administrator, three-layer applied/local-policy, user-resource/peripheral migration-dependency, offline local-network-topology, safe software-registration, and purpose-bound local certificate/trust context after approval, validate typed evidence, supervise approved work, exercise one frozen administrator plan and one separate SYSTEM Collection Sub-plan, protect an assessment package for the local user and optionally one preapproved recipient, reopen one requested artifact safely, exercise warned restricted HTML export, and drive each validation path to one honest terminal outcome.

> [!IMPORTANT]
> The v2 application implements only the narrow device-context, firmware-security, identity/enrollment, direct local-administrator, applied/local-policy, user-resource/peripheral dependency, Local Only network-topology, software-registration, and purpose-bound local certificate/trust slices described below. It is not the complete assessment and does not by itself create a Preview/Supported capability claim. The locally built development artifact is intentionally unsigned and fails the artifact-trust gate, so it cannot self-assert release provenance; repository validation uses closed synthetic fixtures.

## Try the v2 launch safely

You need stable PowerShell Core 7.6 or a later 7.x version. WIN-PCInfo does not install, repair, or change PowerShell for you. See [Runtime prerequisites and safe launch](docs/runtime-prerequisites.md) for beginner-friendly installation, verification, guided and automation examples, troubleshooting, and the complete compatibility boundary.

From a PowerShell 7.6-or-later console:

```powershell
pwsh -NoLogo -NoProfile -File ./build/Build.ps1
pwsh -NoLogo -NoProfile -File ./artifacts/WIN-PCInfo.ps1 -Mode Guided
```

The tracked code under `src/` is the source of truth. `build/Build.ps1` deterministically assembles it into the ignored `artifacts/WIN-PCInfo.ps1`; do not edit the generated file.

Before approving anything, read [Preparation Summary and approval](docs/preparation-summary.md). It explains the two network choices, every disclosure in the summary, guided and automation approval, and the exact Device Readiness operation that approval can start.

To understand how one synthetic source becomes a typed observation, Collector Result Envelope, closed Evidence Coverage State, diagnostic, finding, recommendation, and canonical Assessment Record, read [Assessment Contract validation](docs/assessment-contract-validation.md). It explains the Draft 2020-12 schema, semantic reason codes, I-JSON-style safety rules, and Secret Exclusion boundary in beginner-friendly terms.

To understand the current real collection slice—manufacturer, model, processor, memory, normalized Windows edition/build/architecture, product-key-free activation state, form, virtualization, chassis, and bounded battery/power context—read [Device, Windows, activation, form, virtualization, and power context](docs/device-windows-readiness.md). It explains the exact Windows properties, privacy boundary, claim limits, missing-evidence behavior, report, package, and troubleshooting.

To understand the privileged, read-only firmware-security slice—firmware mode, BIOS/SMBIOS version, Secure Boot state, TPM readiness, virtual/physical limits, follow-up discovery, and beginner guidance—read [Firmware, Secure Boot, and TPM readiness](docs/firmware-readiness.md).

To understand the locale-neutral identity slice—verified Assessment User Context, domain join, Microsoft Entra registration, the default local work-or-school context, bounded SYSTEM MDM-provider evidence, Restricted identifiers, tenant-side questions, and claim limits—read [Registration, join, and enrollment context](docs/identity-enrollment.md).

To understand the bounded mapped-resource, printer, driver, and common-peripheral slice—including its Assessment User boundary, exact source catalog, prohibited material, absence semantics, privacy rules, and advisory migration guidance—read [User resources and peripheral migration dependencies](docs/resource-peripheral-dependencies.md).

To understand the offline network slice—local adapters, profiles, addressing, routes, configured resolvers/proxy, VPN and security registrations, existing local connections, three deliberately unattempted network-dependent checks, privacy boundaries, and proof that Local Only makes zero assessment network requests—read [Local network topology and Local Only](docs/network-topology-and-local-only.md).

To understand the read-only software slice—explicit 32-bit and 64-bit uninstall registration views, inventory-only MSI APIs, Windows package identities, Assessment User context, bounded gaps, Restricted identities, and the prohibition on `Win32_Product` and repair actions—read [Safe Software Inventory](docs/software-inventory.md).

To understand the purpose-bound certificate slice—management, authentication, device identity, code trust, TLS inspection, and service-connectivity questions; separate presence, validity, chain, trust, and key-protection states; offline read-only store access; Restricted fingerprints; and the prohibition on private-key access or trust changes—read [Purpose-bound certificates and local trust](docs/certificate-trust.md).

To understand the separate conservative family/role labels—exact Windows identities, contextual composites, ambiguity, unknown and `NotEvaluated` outcomes, catalog provenance, offline behavior, and why recognition never creates a finding—read [Software Recognition annotations](docs/software-recognition.md).

To understand the direct local-administrator slice—well-known-SID group selection, direct-only membership, unresolved and nested identities, alternate-administrator separation, Restricted evidence, and non-removal guidance—read [Local administrator exposure and execution context](docs/local-administrator-exposure.md).

To understand the policy slice—cached applied Group Policy identity/link/precedence, configured registry signals, local SAM policy, Audit Policy, direct user-right assignments, three-layer evidence semantics, Restricted identifiers, and no-refresh/no-install limits—read [Applied Group Policy and local security policy](docs/effective-policy-assessment.md).

To understand how WIN-PCInfo launches predefined synthetic and real collectors without exposing a shell or plug-in path, read [Process Supervisor](docs/process-supervisor.md). It explains the release-owned executable catalog, compact source identity, suspended Windows Job Object assignment, bounded output, cooperative and hard cancellation, untrusted-output privacy, and verified cleanup.

To understand the finite Assessment Run state machine, stable exit codes, structured progress and heartbeat budgets, device-wide Active Run Lock, cleanup-only crash recovery, package-integrity gate, and failure precedence, read [Assessment Run lifecycle](docs/run-lifecycle.md).

To understand where restricted evidence may exist, what the non-secret Run Recovery Journal records, and why stale recovery refuses ambiguous deletion, read [Evidence Workspace and Stale-run Recovery](docs/evidence-workspace-recovery.md). It includes beginner steps, privacy limits, ordinary-deletion guidance, and recovery troubleshooting.

To understand how the synthetic Assessment Record and report become one locally protected package, and how a restricted viewing session reveals and removes only one requested artifact, read [Protected Evidence Packages and viewing](docs/protected-evidence-package.md). It explains AES-GCM chunks, DPAPI CurrentUser protection, validation, failure handling, privacy limits, and recovery in beginner-friendly terms.

To understand separate consultant Recipient Profile setup, TPM-backed versus Windows-user-bound protection, out-of-band fingerprint confirmation, one-recipient OAEP wrapping, private transfer, historical recipient opening, warned HTML-only export, and Result-sharing Guidance, read [Recipient Profiles and restricted report export](docs/recipient-sharing.md).

To understand why one device-level Windows MDM WMI Bridge source requires LocalSystem, and how WIN-PCInfo prevents that narrow need from becoming a SYSTEM command channel, read [SYSTEM Collection Sub-plan](docs/system-collection-sub-plan.md). It explains the frozen catalog, typed plan, transient activation, exact provenance, evidence confinement, privacy boundary, cleanup proof, and current controlled-client validation limitation.

## Legacy script

`ComputerInfo.ps1` is the legacy implementation and remains available as an outcome and migration reference. It gathers Windows information, but it does **not** implement the v2 safety, privacy, lifecycle, evidence-protection, or runtime contracts. Do not treat its behavior as the v2 launch path.

The legacy instructions and feature inventory below describe only that script.

## Version 2 specification

WIN-PCInfo v2 is defined through a public, decision-led specification and is now being implemented as narrow, verifiable vertical slices.

Start with the [v2 capability-ledger rulebook](docs/spec/capability-ledger.md) to understand how legacy and new capabilities are classified, prioritized, selected for previews, and traced into release evidence. The broader route is indexed in the [WIN-PCInfo v2 product and release specification map](https://github.com/jmanuelng/WIN_PCinfo/issues/1).

## Legacy features

The `ComputerInfo.ps1` script collects the following information:

1. **System Information**: This includes data such as the computer name, manufacturer, model, serial number, BIOS version, operating system version, installed RAM, processor details, and more. This information is gathered using WMI classes and the "systeminfo" command.

2. **User Information**: The script identifies the currently logged-in user and their associated Azure AD accounts. This is done by querying the WMI classes related to user accounts.

3. **Network Information**: The script collects details about the computer's network interfaces, including IP addresses, MAC addresses, and connection status. It also tests network connectivity to Microsoft Intune and Microsoft Defender for Endpoint endpoints. This information is gathered using WMI classes related to network interfaces and the "ping" command.

4. **Enterprise Enrollment DNS Resolution**: The script tests DNS resolution for Enterprise Enrollment and Enterprise Registration, using both the default DNS server and a set of known DNS servers. This is done using the "Resolve-DnsName" cmdlet.

5. **Software Inventory**: The legacy script generates a list of installed software with `Get-WmiObject Win32_Product`. That legacy source can trigger Windows Installer consistency work and is deliberately **not** used by the v2 application. The v2 safe replacement is documented in [Safe Software Inventory](docs/software-inventory.md).

6. **Battery Report**: If the computer is a laptop, the script generates a detailed battery report using the `powercfg /batteryreport` command.

All collected data is written to CSV files for easy analysis and record-keeping.

## Legacy usage

To use the `ComputerInfo.ps1` script, follow these steps:

1. Clone the `WIN_PCinfo` repository or download the `ComputerInfo.ps1` script directly.

2. Review the legacy script and its side effects in a controlled test environment before deciding whether to run it. It does not provide the v2 safety gate.

3. Navigate to the directory where you saved the `ComputerInfo.ps1` script.

4. Run the script by typing `.\ComputerInfo.ps1` and pressing Enter.

The legacy script begins collecting immediately and creates several output files. Prefer the v2 generated launch path when evaluating current v2 work.

## Contributing

Contributions to the `WIN_PCinfo` repository are welcome. If you have a feature request, bug report, or improvement to the script, please open an issue or submit a pull request.

## Author

Created and maintained by Manuel Nieto ([@jmanuelng](https://github.com/jmanuelng)).

## License

The `WIN_PCinfo` repository and the `ComputerInfo.ps1` script are provided under the MIT License. The MIT License is a permissive free software license that puts only very limited restriction on reuse and has, therefore, high license compatibility. It permits users to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of **WIN_PCinfo** - Detailed Computer Information PowerShell Script

## Disclaimer
This script is provided as-is with no warranties or guarantees of any kind. Always test scripts and tools in a controlled environment before deploying them in a production setting.
